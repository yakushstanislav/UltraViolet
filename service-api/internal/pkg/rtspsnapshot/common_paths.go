package rtspsnapshot

import (
	"time"
)

// MaxAutoStreamPaths caps how many URLs the auto snapshot mode will try per
// request (user path first, then this list, deduplicated).
const MaxAutoStreamPaths = 28

// AutoPathExecTimeout returns a per-attempt deadline for auto path probing so a
// single API call cannot run for an unbounded time when many paths are tried.
func AutoPathExecTimeout(global time.Duration) time.Duration {
	const capDur = 7 * time.Second

	if global <= 0 {
		return capDur
	}

	if global < capDur {
		return global
	}

	return capDur
}

// CommonStreamPaths returns vendor-typical RTSP resource paths (Hikvision,
// Dahua, Axis, Ubiquiti, Amcrest, generic NVRs). Order is heuristic; callers
// prepend a user-provided path first when present.
func CommonStreamPaths() []string {
	return []string{
		"/",
		"/live",
		"/stream1",
		"/stream2",
		"/h264",
		"/Streaming/Channels/101",
		"/Streaming/Channels/102",
		"/Streaming/Channels/1",
		"/Streaming/Channels/2",
		"/cam/realmonitor?channel=1&subtype=0",
		"/cam/realmonitor?channel=1&subtype=1",
		"/cam/realmonitor?channel=2&subtype=0",
		"/live/ch00_0",
		"/live/ch00_1",
		"/axis-media/media.amp",
		"/mpeg4/media.amp",
		"/onvif-media/media.amp",
		"/profile1/media.smp",
		"/profile2/media.smp",
		"/s0",
		"/11",
		"/12",
		"/ch0",
		"/ch1",
		"/videoMain",
		"/videoSub",
		"/ucast/11",
		"/ucast/12",
		"/LiveMedia/ch1/Media1",
	}
}

// SnapshotPaths builds an ordered, deduplicated path list for one snapshot
// request. When autoTryCommon is false, snapshotPath is the only element.
func SnapshotPaths(snapshotPath string, autoTryCommon bool) []string {
	if !autoTryCommon {
		return []string{snapshotPath}
	}

	seen := make(map[string]struct{}, MaxAutoStreamPaths+1)

	out := make([]string, 0, MaxAutoStreamPaths)

	add := func(p string) {
		if len(out) >= MaxAutoStreamPaths {
			return
		}

		if p == "" {
			return
		}

		if p[0] != '/' {
			p = "/" + p
		}

		if _, ok := seen[p]; ok {
			return
		}

		seen[p] = struct{}{}
		out = append(out, p)
	}

	add(snapshotPath)

	for _, p := range CommonStreamPaths() {
		add(p)

		if len(out) >= MaxAutoStreamPaths {
			break
		}
	}

	return out
}
