package crush

import (
	"errors"
	"fmt"
	"math"
)

var ErrPlacement = errors.New("invalid CRUSH placement")

const maxCertifiedReplicas = 64

const itemNone = int32(0x7fffffff)

type permutation struct {
	x     uint32
	count uint32
	items []uint32
}

type placement struct {
	crush        *Map
	weights      []uint32
	permutations map[int32]*permutation
}

// Place executes a decoded replicated straw2 rule for seed and returns at most
// replicas OSD IDs. osdWeights are Ceph 16.16 override weights used only to
// filter selected OSDs.
func (crushMap *Map) Place(ruleID, seed uint32, replicas int, osdWeights []uint32) ([]int32, error) {
	if crushMap == nil || replicas <= 0 || replicas > maxCertifiedReplicas {
		return nil, ErrPlacement
	}
	rule, ok := crushMap.Rules[ruleID]
	if !ok {
		return nil, fmt.Errorf("%w: rule %d does not exist", ErrPlacement, ruleID)
	}
	if rule.Type != RuleTypeReplicated && rule.Type != RuleTypeErasure {
		return nil, fmt.Errorf("%w: rule %d type %d", ErrPlacement, ruleID, rule.Type)
	}
	if err := crushMap.validateCertifiedRule(rule); err != nil {
		return nil, err
	}
	if err := crushMap.validateGraph(); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrPlacement, err)
	}
	executor := placement{crush: crushMap, weights: osdWeights, permutations: make(map[int32]*permutation)}
	return executor.rule(rule, seed, replicas)
}

func (crushMap *Map) validateCertifiedRule(rule Rule) error {
	takeIndex := 0
	if rule.Type == RuleTypeReplicated {
		if len(rule.Steps) != 3 || rule.Steps[0].Operation != RuleTake || rule.Steps[2] != (RuleStep{Operation: RuleEmit}) {
			return fmt.Errorf("%w: rule is outside certified replicated profile", ErrPlacement)
		}
		choose := rule.Steps[1]
		if choose == (RuleStep{Operation: RuleChooseFirstN}) {
			// Flat replicated rule.
		} else if choose.Operation != RuleChooseleafFirstN || choose.Argument1 != 0 || choose.Argument2 <= 0 || !crushMap.hasBucketType(uint16(choose.Argument2)) {
			return fmt.Errorf("%w: rule is outside certified replicated profile", ErrPlacement)
		}
	} else {
		if len(rule.Steps) != 5 || rule.Steps[0] != (RuleStep{Operation: RuleSetChooseleafTries, Argument1: 5}) || rule.Steps[1] != (RuleStep{Operation: RuleSetChooseTries, Argument1: 100}) || rule.Steps[2].Operation != RuleTake || rule.Steps[3] != (RuleStep{Operation: RuleChooseIndep}) || rule.Steps[4].Operation != RuleEmit {
			return fmt.Errorf("%w: rule is outside certified erasure profile", ErrPlacement)
		}
		takeIndex = 2
	}
	if _, ok := crushMap.Buckets[rule.Steps[takeIndex].Argument1]; !ok {
		return fmt.Errorf("%w: TAKE root %d does not exist", ErrPlacement, rule.Steps[takeIndex].Argument1)
	}
	if _, shadow := crushMap.classShadowBuckets[rule.Steps[takeIndex].Argument1]; shadow {
		return fmt.Errorf("%w: class-constrained root", ErrPlacement)
	}
	if crushMap.ChooseLocalTries != 0 || crushMap.ChooseLocalFallbackTries != 0 || crushMap.ChooseTotalTries != 50 || crushMap.ChooseleafDescendOnce != 1 || crushMap.ChooseleafVaryR != 1 || crushMap.ChooseleafStable != 1 {
		return fmt.Errorf("%w: tunables are outside certified Tentacle profile", ErrPlacement)
	}
	return nil
}

func (crushMap *Map) hasBucketType(bucketType uint16) bool {
	for _, bucket := range crushMap.Buckets {
		if bucket.Type == bucketType {
			return true
		}
	}
	return false
}

func (executor *placement) rule(rule Rule, seed uint32, resultMaximum int) ([]int32, error) {
	working := make([]int32, resultMaximum)
	output := make([]int32, resultMaximum)
	leaves := make([]int32, resultMaximum)
	workingSize := 0
	result := make([]int32, 0, resultMaximum)
	chooseTries := executor.crush.ChooseTotalTries + 1
	chooseleafTries := uint32(0)
	recurseTries := chooseTries
	if executor.crush.ChooseleafDescendOnce != 0 {
		recurseTries = 1
	}

	for _, step := range rule.Steps {
		switch step.Operation {
		case RuleSetChooseTries:
			if step.Argument1 > 0 {
				chooseTries = uint32(step.Argument1)
			}
		case RuleSetChooseleafTries:
			if step.Argument1 > 0 {
				chooseleafTries = uint32(step.Argument1)
			}
		case RuleTake:
			if !executor.validTake(step.Argument1) {
				continue
			}
			working[0] = step.Argument1
			workingSize = 1
		case RuleChooseFirstN, RuleChooseleafFirstN, RuleChooseIndep:
			if workingSize == 0 {
				continue
			}
			outputSize := 0
			for index := 0; index < workingSize; index++ {
				number := int(step.Argument1)
				if number <= 0 {
					number += resultMaximum
					if number <= 0 {
						continue
					}
				}
				bucket, ok := executor.crush.Buckets[working[index]]
				if !ok {
					continue
				}
				recurseToLeaf := step.Operation == RuleChooseleafFirstN
				if step.Operation == RuleChooseIndep {
					count := min(number, resultMaximum-outputSize)
					recurse := chooseleafTries
					if recurse == 0 {
						recurse = 1
					}
					executor.chooseIndep(bucket, seed, count, number, int(step.Argument2), output, outputSize, chooseTries, recurse, recurseToLeaf, leaves, 0)
					outputSize += count
				} else {
					chosen, err := executor.chooseFirstN(
						bucket, seed, number, step.Argument2,
						output[outputSize:], 0, resultMaximum-outputSize,
						chooseTries, recurseTries, executor.crush.ChooseLocalTries,
						executor.crush.ChooseLocalFallbackTries, recurseToLeaf,
						uint32(executor.crush.ChooseleafVaryR), executor.crush.ChooseleafStable != 0,
						leaves[outputSize:], 0,
					)
					if err != nil {
						return nil, err
					}
					outputSize += chosen
				}
			}
			if step.Operation == RuleChooseleafFirstN {
				copy(output[:outputSize], leaves[:outputSize])
			}
			working, output = output, working
			workingSize = outputSize
		case RuleEmit:
			remaining := resultMaximum - len(result)
			if remaining > workingSize {
				remaining = workingSize
			}
			result = append(result, working[:remaining]...)
			workingSize = 0
		default:
			return nil, fmt.Errorf("%w: rule operation %d", ErrPlacement, step.Operation)
		}
	}
	return result, nil
}

func (executor *placement) chooseIndep(bucket Bucket, seed uint32, left, replicas, targetType int, output []int32, outputPosition int, tries, recurseTries uint32, recurseToLeaf bool, leaves []int32, parentR int) {
	end := outputPosition + left
	for position := outputPosition; position < end; position++ {
		output[position] = itemNone
		if leaves != nil {
			leaves[position] = itemNone
		}
	}
	for failure := uint32(0); left > 0 && failure < tries; failure++ {
		for position := outputPosition; position < end; position++ {
			if output[position] != itemNone {
				continue
			}
			current := bucket
			for {
				r := position + parentR + replicas*int(failure)
				if len(current.Items) == 0 {
					break
				}
				item := straw2Choose(current, seed, r)
				if item >= executor.crush.MaxDevices {
					left--
					break
				}
				itemType := int32(0)
				if item < 0 {
					child, ok := executor.crush.Buckets[item]
					if !ok {
						left--
						break
					}
					itemType = int32(child.Type)
				}
				if itemType != int32(targetType) {
					if item >= 0 {
						left--
						break
					}
					current = executor.crush.Buckets[item]
					continue
				}
				collision := false
				for index := outputPosition; index < end; index++ {
					if output[index] == item {
						collision = true
						break
					}
				}
				if collision {
					break
				}
				if recurseToLeaf {
					if item < 0 {
						executor.chooseIndep(executor.crush.Buckets[item], seed, 1, replicas, 0, leaves, position, recurseTries, 0, false, nil, r)
						if leaves[position] == itemNone {
							break
						}
					} else {
						leaves[position] = item
					}
				}
				if itemType == 0 && executor.isOut(item, seed) {
					break
				}
				output[position] = item
				left--
				break
			}
		}
	}
}

func (executor *placement) validTake(item int32) bool {
	if item >= 0 {
		return item < executor.crush.MaxDevices
	}
	_, ok := executor.crush.Buckets[item]
	return ok
}

func (executor *placement) chooseFirstN(
	bucket Bucket, seed uint32, replicas int, targetType int32,
	output []int32, outputPosition, outputSize int,
	tries, recurseTries, localRetries, localFallbackRetries uint32,
	recurseToLeaf bool, varyR uint32, stable bool, leaves []int32, parentR int,
) (int, error) {
	count := outputSize
	firstReplica := outputPosition
	if stable {
		firstReplica = 0
	}
	for replica := firstReplica; replica < replicas && count > 0; replica++ {
		totalFailures := uint32(0)
		skipReplica := false
		var item int32
		for retryDescent := true; retryDescent; {
			retryDescent = false
			current := bucket
			localFailures := uint32(0)
			for retryBucket := true; retryBucket; {
				retryBucket = false
				collide, reject := false, false
				r := replica + parentR + int(totalFailures)
				if len(current.Items) == 0 {
					reject = true
				} else if localFallbackRetries > 0 && localFailures >= uint32(len(current.Items)>>1) && localFailures > localFallbackRetries {
					item = executor.permutationChoose(current, seed, r)
				} else {
					item = straw2Choose(current, seed, r)
				}

				if !reject && item >= executor.crush.MaxDevices {
					skipReplica = true
					break
				}

				itemType := int32(0)
				if !reject && item < 0 {
					child, ok := executor.crush.Buckets[item]
					if !ok {
						skipReplica = true
						break
					}
					itemType = int32(child.Type)
				}
				if !reject && itemType != targetType {
					if item >= 0 {
						skipReplica = true
						break
					}
					current = executor.crush.Buckets[item]
					retryBucket = true
					continue
				}

				if !reject {
					for index := 0; index < outputPosition; index++ {
						if output[index] == item {
							collide = true
							break
						}
					}
				}

				if !reject && !collide && recurseToLeaf {
					if item < 0 {
						subR := 0
						if varyR != 0 {
							subR = r >> (varyR - 1)
						}
						recursiveReplicas := outputPosition + 1
						if stable {
							recursiveReplicas = 1
						}
						chosen, err := executor.chooseFirstN(
							executor.crush.Buckets[item], seed, recursiveReplicas, 0,
							leaves, outputPosition, count, recurseTries, 0,
							localRetries, localFallbackRetries, false, varyR, stable, nil, subR,
						)
						if err != nil {
							return outputPosition, err
						}
						if chosen <= outputPosition {
							reject = true
						}
					} else {
						leaves[outputPosition] = item
					}
				}

				if !reject && !collide && itemType == 0 {
					reject = executor.isOut(item, seed)
				}
				if reject || collide {
					totalFailures++
					localFailures++
					if collide && localFailures <= localRetries {
						retryBucket = true
					} else if localFallbackRetries > 0 && localFailures <= uint32(len(current.Items))+localFallbackRetries {
						retryBucket = true
					} else if totalFailures < tries {
						retryDescent = true
					} else {
						skipReplica = true
					}
				}
			}
		}
		if skipReplica {
			continue
		}
		output[outputPosition] = item
		outputPosition++
		count--
	}
	return outputPosition, nil
}

func straw2Choose(bucket Bucket, seed uint32, replica int) int32 {
	high := 0
	highDraw := int64(0)
	for index, weight := range bucket.ItemWeights {
		draw := int64(math.MinInt64)
		if weight != 0 {
			random := Hash32Triple(seed, uint32(bucket.Items[index]), uint32(replica)) & 0xffff
			logarithm := int64(crushLn(random)) - int64(1<<48)
			draw = logarithm / int64(weight)
		}
		if index == 0 || draw > highDraw {
			high = index
			highDraw = draw
		}
	}
	return bucket.Items[high]
}

func (executor *placement) permutationChoose(bucket Bucket, seed uint32, replica int) int32 {
	state := executor.permutations[bucket.ID]
	if state == nil {
		state = &permutation{items: make([]uint32, len(bucket.Items))}
		executor.permutations[bucket.ID] = state
	}
	position := uint32(replica) % uint32(len(bucket.Items))
	if state.x != seed || state.count == 0 {
		state.x = seed
		if position == 0 {
			selected := Hash32Triple(seed, uint32(bucket.ID), 0) % uint32(len(bucket.Items))
			state.items[0] = selected
			state.count = 0xffff
			return bucket.Items[selected]
		}
		for index := range state.items {
			state.items[index] = uint32(index)
		}
		state.count = 0
	} else if state.count == 0xffff {
		for index := 1; index < len(state.items); index++ {
			state.items[index] = uint32(index)
		}
		state.items[state.items[0]] = 0
		state.count = 1
	}
	for state.count <= position {
		current := state.count
		if current < uint32(len(bucket.Items)-1) {
			offset := Hash32Triple(seed, uint32(bucket.ID), current) % (uint32(len(bucket.Items)) - current)
			if offset != 0 {
				state.items[current], state.items[current+offset] = state.items[current+offset], state.items[current]
			}
		}
		state.count++
	}
	return bucket.Items[state.items[position]]
}

func (executor *placement) isOut(item int32, seed uint32) bool {
	if item < 0 || int(item) >= len(executor.weights) {
		return true
	}
	weight := executor.weights[item]
	if weight >= 0x10000 {
		return false
	}
	if weight == 0 {
		return true
	}
	return Hash32Pair(seed, uint32(item))&0xffff >= weight
}
