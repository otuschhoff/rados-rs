package maps

import (
	"errors"
	"fmt"

	"github.com/otuschhoff/go-librados/internal/crush"
)

var ErrUnsupportedPlacement = errors.New("unsupported placement")

const (
	objectHashRJenkins = 2
	poolFlagHashPSPool = 1 << 0
	crushItemNone      = int32(0x7fffffff)
)

type ObjectPlacement struct {
	RawHash       uint32
	RawPG         PG
	PG            PG
	PlacementSeed uint32
	Raw           []int32
	Up            []int32
	UpPrimary     int32
	Acting        []int32
	ActingPrimary int32
	PrimaryShard  int8
	Sharded       bool
}

func (osdMap *OSDMap) MapObject(poolID int64, object, locator, namespace string) (ObjectPlacement, error) {
	return osdMap.MapRawHash(poolID, crush.ObjectHash(object, locator, namespace))
}

func (osdMap *OSDMap) MapRawHash(poolID int64, hash uint32) (ObjectPlacement, error) {
	if poolID < 0 {
		return ObjectPlacement{}, fmt.Errorf("%w: negative pool %d", ErrUnsupportedPlacement, poolID)
	}
	pool, ok := osdMap.pools[poolID]
	if !ok {
		return ObjectPlacement{}, fmt.Errorf("%w: pool %d does not exist", ErrUnsupportedPlacement, poolID)
	}
	if pool.objectHash != objectHashRJenkins {
		return ObjectPlacement{}, fmt.Errorf("%w: object hash %d", ErrUnsupportedPlacement, pool.objectHash)
	}
	if pool.flags&poolFlagHashPSPool == 0 {
		return ObjectPlacement{}, fmt.Errorf("%w: pool %d does not use HASHPSPOOL", ErrUnsupportedPlacement, poolID)
	}
	if pool.pgCount == 0 || pool.placementPGCount == 0 || pool.placementPGCount > pool.pgCount {
		return ObjectPlacement{}, fmt.Errorf("%w: pool %d has invalid PG geometry", ErrUnsupportedPlacement, poolID)
	}
	raw := PG{Pool: uint64(poolID), Seed: hash, Preferred: -1}
	actual := raw
	actual.Seed = crush.StableMod(hash, pool.pgCount)
	placementPG := crush.StableMod(hash, pool.placementPGCount)
	placementSeed := crush.Hash32Pair(placementPG, uint32(poolID))
	return ObjectPlacement{RawHash: hash, RawPG: raw, PG: actual, PlacementSeed: placementSeed}, nil
}

func (osdMap *OSDMap) PlaceObject(poolID int64, object, locator, namespace string) (ObjectPlacement, error) {
	placement, err := osdMap.MapObject(poolID, object, locator, namespace)
	if err != nil {
		return ObjectPlacement{}, err
	}
	return osdMap.placeMapped(poolID, placement)
}

func (osdMap *OSDMap) PlaceRawHash(poolID int64, hash uint32) (ObjectPlacement, error) {
	placement, err := osdMap.MapRawHash(poolID, hash)
	if err != nil {
		return ObjectPlacement{}, err
	}
	return osdMap.placeMapped(poolID, placement)
}

func (osdMap *OSDMap) placeMapped(poolID int64, placement ObjectPlacement) (ObjectPlacement, error) {
	pool := osdMap.pools[poolID]
	if pool.poolType != poolTypeReplicated && pool.poolType != poolTypeErasure {
		return ObjectPlacement{}, fmt.Errorf("%w: pool type %d", ErrUnsupportedPlacement, pool.poolType)
	}
	if pool.size == 0 {
		return ObjectPlacement{}, fmt.Errorf("%w: pool %d has zero replicas", ErrUnsupportedPlacement, poolID)
	}
	structuralLimit := max(uint32(len(osdMap.crushData))/4, 1)
	crushMap, err := crush.DecodeMap(osdMap.crushData, crush.DecodeLimits{
		MaxBytes: uint32(len(osdMap.crushData)), MaxBuckets: structuralLimit,
		MaxRules: structuralLimit, MaxItems: structuralLimit, MaxNames: structuralLimit,
	})
	if err != nil {
		return ObjectPlacement{}, fmt.Errorf("%w: %v", ErrUnsupportedPlacement, err)
	}
	raw, err := crushMap.Place(uint32(pool.crushRule), placement.PlacementSeed, int(pool.size), osdMap.osdWeight)
	if err != nil {
		return ObjectPlacement{}, fmt.Errorf("%w: %v", ErrUnsupportedPlacement, err)
	}
	placement.Raw = append([]int32(nil), raw...)
	if err := osdMap.validateUpmap(placement.PG); err != nil {
		return ObjectPlacement{}, err
	}
	mapped := osdMap.applyUpmap(placement.PG, raw)
	up := osdMap.onlyUp(mapped)
	upPrimary := firstOSD(up)
	osdMap.applyPrimaryAffinity(placement.PlacementSeed, up, &upPrimary)
	acting, actingPrimary, err := osdMap.tempMapping(placement.PG)
	if err != nil {
		return ObjectPlacement{}, err
	}
	if len(acting) == 0 {
		acting = append([]int32(nil), up...)
		if actingPrimary == -1 {
			actingPrimary = upPrimary
		}
	}
	if actingPrimary != -1 && !containsOSD(acting, actingPrimary) {
		return ObjectPlacement{}, fmt.Errorf("%w: temporary primary %d is not in the acting set", ErrUnsupportedPlacement, actingPrimary)
	}
	placement.Up = up
	placement.UpPrimary = upPrimary
	placement.Acting = acting
	placement.ActingPrimary = actingPrimary
	if pool.poolType == poolTypeErasure {
		for index, osd := range acting {
			if osd == actingPrimary {
				if index > 127 {
					return ObjectPlacement{}, fmt.Errorf("%w: primary shard %d exceeds wire range", ErrUnsupportedPlacement, index)
				}
				placement.PrimaryShard = int8(index)
				placement.Sharded = true
				break
			}
		}
	}
	return placement, nil
}

func (osdMap *OSDMap) applyUpmap(pg PG, source []int32) []int32 {
	result := append([]int32(nil), source...)
	if replacement, ok := osdMap.pgUpmap[pg]; ok {
		valid := true
		for _, osd := range replacement {
			if osd != crushItemNone && osd >= 0 && int(osd) < len(osdMap.osdWeight) && osdMap.osdWeight[osd] == 0 {
				valid = false
				break
			}
		}
		if valid {
			result = append([]int32(nil), replacement...)
		} else {
			return result
		}
	}
	for _, remap := range osdMap.pgUpmapItems[pg] {
		targetExists, position := false, -1
		for index, osd := range result {
			if osd == remap.To {
				targetExists = true
				break
			}
			targetOut := remap.To != crushItemNone && remap.To >= 0 && int(remap.To) < len(osdMap.osdWeight) && osdMap.osdWeight[remap.To] == 0
			if osd == remap.From && position < 0 && !targetOut {
				position = index
			}
		}
		if !targetExists && position >= 0 {
			result[position] = remap.To
		}
	}
	if primary, ok := osdMap.pgUpmapPrimaries[pg]; ok && primary != crushItemNone && primary >= 0 && int(primary) < len(osdMap.osdWeight) && osdMap.osdWeight[primary] != 0 {
		for index := 1; index < len(result); index++ {
			if result[index] == primary {
				result[0], result[index] = result[index], result[0]
				break
			}
		}
	}
	return result
}

func (osdMap *OSDMap) validateUpmap(pg PG) error {
	if replacement, ok := osdMap.pgUpmap[pg]; ok {
		if err := osdMap.validatePlacementSet("pg_upmap", replacement); err != nil {
			return err
		}
	}
	for _, remap := range osdMap.pgUpmapItems[pg] {
		if remap.To != crushItemNone && !osdMap.exists(remap.To) {
			return fmt.Errorf("%w: pg_upmap_items references nonexistent osd.%d", ErrUnsupportedPlacement, remap.To)
		}
	}
	return nil
}

func (osdMap *OSDMap) onlyUp(source []int32) []int32 {
	result := make([]int32, 0, len(source))
	for _, osd := range source {
		if osdMap.isUp(osd) {
			result = append(result, osd)
		}
	}
	return result
}

func (osdMap *OSDMap) tempMapping(pg PG) ([]int32, int32, error) {
	primary := int32(-1)
	if override, ok := osdMap.primaryTemp[pg]; ok {
		primary = override
	}
	source, ok := osdMap.pgTemp[pg]
	if !ok {
		return nil, primary, nil
	}
	if err := osdMap.validatePlacementSet("pg_temp", source); err != nil {
		return nil, -1, err
	}
	result := osdMap.onlyUp(source)
	if primary == -1 {
		primary = firstOSD(result)
	}
	return result, primary, nil
}

func (osdMap *OSDMap) applyPrimaryAffinity(seed uint32, osds []int32, primary *int32) {
	if len(osdMap.primaryAffinity) == 0 {
		return
	}
	position := -1
	for index, osd := range osds {
		if osd == crushItemNone || osd < 0 || int(osd) >= len(osdMap.primaryAffinity) {
			continue
		}
		affinity := osdMap.primaryAffinity[osd]
		if affinity < defaultPrimaryAffinity && crush.Hash32Pair(seed, uint32(osd))>>16 >= affinity {
			if position < 0 {
				position = index
			}
			continue
		}
		position = index
		break
	}
	if position < 0 {
		return
	}
	*primary = osds[position]
	if position > 0 {
		copy(osds[1:position+1], osds[:position])
		osds[0] = *primary
	}
}

func (osdMap *OSDMap) exists(osd int32) bool {
	return osd >= 0 && int(osd) < len(osdMap.osdState) && osdMap.osdState[osd]&(1<<0) != 0
}

func (osdMap *OSDMap) isUp(osd int32) bool {
	return osdMap.exists(osd) && osdMap.osdState[osd]&(1<<1) != 0
}

func (osdMap *OSDMap) validatePlacementSet(name string, osds []int32) error {
	seen := make(map[int32]struct{}, len(osds))
	for _, osd := range osds {
		if osd == crushItemNone {
			continue
		}
		if !osdMap.exists(osd) {
			return fmt.Errorf("%w: %s references nonexistent osd.%d", ErrUnsupportedPlacement, name, osd)
		}
		if _, duplicate := seen[osd]; duplicate {
			return fmt.Errorf("%w: %s contains duplicate osd.%d", ErrUnsupportedPlacement, name, osd)
		}
		seen[osd] = struct{}{}
	}
	return nil
}

func firstOSD(osds []int32) int32 {
	for _, osd := range osds {
		if osd != crushItemNone {
			return osd
		}
	}
	return -1
}

func containsOSD(osds []int32, target int32) bool {
	for _, osd := range osds {
		if osd == target {
			return true
		}
	}
	return false
}
