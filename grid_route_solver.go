package main

import (
	"container/heap"
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"math"
	"sort"
	"strconv"
	"strings"
	"time"
)

type gridGraphEdge struct {
	From        string
	To          string
	LatencyMs   float64
	JitterMs    float64
	LossPct     float64
	Reliability float64
}

type gridPathState struct {
	Nodes       []string
	Cost        float64
	LatencyMs   float64
	JitterMs    float64
	LossPct     float64
	Reliability float64
}

type gridPathPriorityQueue []gridPathState

func (pq gridPathPriorityQueue) Len() int { return len(pq) }

func (pq gridPathPriorityQueue) Less(i, j int) bool {
	if pq[i].Cost == pq[j].Cost {
		return len(pq[i].Nodes) < len(pq[j].Nodes)
	}
	return pq[i].Cost < pq[j].Cost
}

func (pq gridPathPriorityQueue) Swap(i, j int) { pq[i], pq[j] = pq[j], pq[i] }

func (pq *gridPathPriorityQueue) Push(x interface{}) {
	*pq = append(*pq, x.(gridPathState))
}

func (pq *gridPathPriorityQueue) Pop() interface{} {
	old := *pq
	n := len(old)
	item := old[n-1]
	*pq = old[:n-1]
	return item
}

func buildWeightedTopKRoutesFromGraph(routes []RouteDescriptor, sourceNode, destinationNode string, maxHop, topK, pathTTLSeconds int) []RouteDescriptor {
	sourceNode = strings.TrimSpace(sourceNode)
	destinationNode = strings.TrimSpace(destinationNode)
	if sourceNode == "" || destinationNode == "" || sourceNode == destinationNode {
		return nil
	}
	if maxHop <= 0 {
		maxHop = 128
	}
	if topK <= 0 {
		topK = 3
	}
	if pathTTLSeconds <= 0 {
		pathTTLSeconds = 120
	}

	graph := buildGridGraph(routes)
	if len(graph[sourceNode]) == 0 {
		return nil
	}

	now := time.Now().UTC()
	epochBase := now.UnixNano()

	pq := &gridPathPriorityQueue{
		{
			Nodes:       []string{sourceNode},
			Cost:        0,
			LatencyMs:   0,
			JitterMs:    0,
			LossPct:     0,
			Reliability: 1.0,
		},
	}
	heap.Init(pq)

	maxExpansions := 12000
	expansions := 0
	results := make([]RouteDescriptor, 0, topK)
	seenPath := make(map[string]struct{}, topK*2)

	for pq.Len() > 0 && len(results) < topK && expansions < maxExpansions {
		state := heap.Pop(pq).(gridPathState)
		currentNode := state.Nodes[len(state.Nodes)-1]
		if currentNode == destinationNode && len(state.Nodes) > 1 {
			pathSig := strings.Join(state.Nodes, "->")
			if _, exists := seenPath[pathSig]; exists {
				continue
			}
			seenPath[pathSig] = struct{}{}

			routeID := makeDijkstraRouteID(sourceNode, destinationNode, state.Nodes)
			latency := int64(math.Round(state.LatencyMs))
			if latency <= 0 {
				latency = int64((len(state.Nodes) - 1) * 15)
			}
			reliability := clampFloat(state.Reliability, 0.01, 1.0)
			results = append(results, RouteDescriptor{
				RouteID:          routeID,
				SourceNode:       sourceNode,
				DestinationNode:  destinationNode,
				Hops:             append([]string(nil), state.Nodes...),
				ReliabilityScore: reliability,
				LatencyMs:        latency,
				Epoch:            epochBase + int64(len(results)+1),
				ExpiresAt:        now.Add(time.Duration(pathTTLSeconds) * time.Second).Unix(),
				Metadata: map[string]string{
					"planner":   "dijkstra",
					"cost":      fmt.Sprintf("%.6f", state.Cost),
					"jitter_ms": fmt.Sprintf("%.3f", state.JitterMs),
					"loss_pct":  fmt.Sprintf("%.3f", state.LossPct),
				},
			})
			continue
		}

		hops := len(state.Nodes) - 1
		if hops >= maxHop {
			continue
		}

		for _, edge := range graph[currentNode] {
			nextNode := strings.TrimSpace(edge.To)
			if nextNode == "" {
				continue
			}
			if containsGridPathNode(state.Nodes, nextNode) {
				continue
			}

			nextState := gridPathState{
				Nodes:       append(append([]string(nil), state.Nodes...), nextNode),
				Cost:        state.Cost + gridEdgeQualityCost(edge),
				LatencyMs:   state.LatencyMs + edge.LatencyMs,
				JitterMs:    state.JitterMs + edge.JitterMs,
				LossPct:     state.LossPct + edge.LossPct,
				Reliability: clampFloat(state.Reliability*edge.Reliability, 0.0001, 1.0),
			}
			heap.Push(pq, nextState)
		}
		expansions++
	}

	sort.Slice(results, func(i, j int) bool {
		iCost := routeQualityCost(results[i])
		jCost := routeQualityCost(results[j])
		if iCost == jCost {
			return results[i].Epoch > results[j].Epoch
		}
		return iCost < jCost
	})
	return results
}

func buildGridGraph(routes []RouteDescriptor) map[string][]gridGraphEdge {
	graph := make(map[string][]gridGraphEdge)
	edgeByKey := make(map[string]gridGraphEdge)
	now := time.Now().UTC().Unix()

	for _, route := range routes {
		if route.ExpiresAt > 0 && route.ExpiresAt < now {
			continue
		}
		hops := normalizeRouteHops(route.Hops)
		if len(hops) < 2 {
			continue
		}
		segments := len(hops) - 1
		if segments <= 0 {
			continue
		}

		totalLatency := float64(route.LatencyMs)
		if totalLatency <= 0 {
			totalLatency = float64(segments * 15)
		}
		totalJitter := routeMetadataFloat(route.Metadata, "jitter_ms", "jitter")
		totalLoss := routeMetadataFloat(route.Metadata, "loss_pct", "packet_loss_pct", "loss")
		if totalLoss < 0 {
			totalLoss = 0
		}
		reliability := route.ReliabilityScore
		if reliability <= 0 {
			reliability = 0.5
		}
		reliability = clampFloat(reliability, 0.01, 1.0)
		perEdgeRel := math.Pow(reliability, 1.0/float64(segments))

		for i := 0; i < segments; i++ {
			fromNode := hops[i]
			toNode := hops[i+1]
			if fromNode == "" || toNode == "" || fromNode == toNode {
				continue
			}
			edge := gridGraphEdge{
				From:        fromNode,
				To:          toNode,
				LatencyMs:   totalLatency / float64(segments),
				JitterMs:    totalJitter / float64(segments),
				LossPct:     totalLoss / float64(segments),
				Reliability: clampFloat(perEdgeRel, 0.01, 1.0),
			}
			key := fromNode + "->" + toNode
			existing, exists := edgeByKey[key]
			if !exists || gridEdgeQualityCost(edge) < gridEdgeQualityCost(existing) {
				edgeByKey[key] = edge
			}
		}
	}

	for _, edge := range edgeByKey {
		graph[edge.From] = append(graph[edge.From], edge)
	}
	for fromNode := range graph {
		sort.Slice(graph[fromNode], func(i, j int) bool {
			return gridEdgeQualityCost(graph[fromNode][i]) < gridEdgeQualityCost(graph[fromNode][j])
		})
	}
	return graph
}

func gridEdgeQualityCost(edge gridGraphEdge) float64 {
	latency := edge.LatencyMs
	if latency <= 0 {
		latency = 1
	}
	jitter := edge.JitterMs
	if jitter < 0 {
		jitter = 0
	}
	loss := edge.LossPct
	if loss < 0 {
		loss = 0
	}
	reliability := clampFloat(edge.Reliability, 0.01, 1.0)
	// Lower cost is better. This can be used by Dijkstra / k-shortest search.
	return 1.0 + latency*0.02 + jitter*0.05 + loss*2.0 + (1.0/reliability)*0.5
}

func normalizeRouteHops(hops []string) []string {
	if len(hops) == 0 {
		return nil
	}
	out := make([]string, 0, len(hops))
	for _, hop := range hops {
		h := strings.TrimSpace(hop)
		if h == "" {
			continue
		}
		out = append(out, h)
	}
	return out
}

func containsGridPathNode(path []string, node string) bool {
	node = strings.TrimSpace(node)
	if node == "" {
		return false
	}
	for _, item := range path {
		if strings.TrimSpace(item) == node {
			return true
		}
	}
	return false
}

func clampFloat(v, minV, maxV float64) float64 {
	if v < minV {
		return minV
	}
	if v > maxV {
		return maxV
	}
	return v
}

func makeDijkstraRouteID(sourceNode, destinationNode string, hops []string) string {
	builder := strings.Builder{}
	builder.WriteString(sourceNode)
	builder.WriteString("->")
	builder.WriteString(destinationNode)
	builder.WriteString("::")
	builder.WriteString(strings.Join(hops, "->"))
	sum := sha1.Sum([]byte(builder.String()))
	hexID := hex.EncodeToString(sum[:])
	return "dijkstra-" + hexID[:16]
}

func mergeRouteDescriptors(primary []RouteDescriptor, extra []RouteDescriptor, limit int) []RouteDescriptor {
	if len(primary) == 0 && len(extra) == 0 {
		return nil
	}
	if limit <= 0 {
		limit = 16
	}
	seenPath := make(map[string]struct{}, len(primary)+len(extra))
	out := make([]RouteDescriptor, 0, len(primary)+len(extra))
	appendRoute := func(route RouteDescriptor) {
		hops := normalizeRouteHops(route.Hops)
		if len(hops) < 2 {
			return
		}
		pathKey := strings.Join(hops, "->")
		if _, exists := seenPath[pathKey]; exists {
			return
		}
		seenPath[pathKey] = struct{}{}
		out = append(out, route)
	}
	for _, route := range primary {
		appendRoute(route)
		if len(out) >= limit {
			return out[:limit]
		}
	}
	for _, route := range extra {
		appendRoute(route)
		if len(out) >= limit {
			break
		}
	}
	sort.Slice(out, func(i, j int) bool {
		iCost := routeQualityCost(out[i])
		jCost := routeQualityCost(out[j])
		if iCost == jCost {
			return out[i].Epoch > out[j].Epoch
		}
		return iCost < jCost
	})
	if len(out) > limit {
		out = out[:limit]
	}
	return out
}

func routePriorityKey(c PathCandidate) string {
	hops := normalizeRouteHops(c.Hops)
	if len(hops) > 0 {
		return strings.Join(hops, "->")
	}
	routeID := strings.TrimSpace(c.RouteID)
	if routeID != "" {
		return routeID
	}
	nextHop := strings.TrimSpace(c.NextHop)
	if nextHop != "" {
		return nextHop + "|" + strconv.FormatInt(c.RouteEpoch, 10)
	}
	return "relay"
}
