package stages

import (
	"strings"
	"sync"
	"time"

	"github.com/go-kit/log"
	"github.com/go-kit/log/level"
	"github.com/mitchellh/mapstructure"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/common/model"

	"github.com/grafana/loki/v3/pkg/util/flagext"
)

const (
	RFC3339Nano              = "RFC3339Nano"
	MaxPartialLinesSize      = 100 // Max buffer size to hold partial lines.
	DefaultMaxPartialLineAge = time.Minute
)

// NewDocker creates a Docker json log format specific pipeline stage.
func NewDocker(logger log.Logger, registerer prometheus.Registerer) (Stage, error) {
	stages := PipelineStages{
		PipelineStage{
			StageTypeJSON: JSONConfig{
				Expressions: map[string]string{
					"output":    "log",
					"stream":    "stream",
					"timestamp": "time",
				},
			}},
		PipelineStage{
			StageTypeLabel: LabelsConfig{
				"stream": nil,
			}},
		PipelineStage{
			StageTypeTimestamp: TimestampConfig{
				Source: "timestamp",
				Format: RFC3339Nano,
			}},
		PipelineStage{
			StageTypeOutput: OutputConfig{
				"output",
			},
		}}
	return NewPipeline(logger, stages, nil, registerer)
}

type cri struct {
	// bounded buffer for CRI-O Partial logs lines (identified with tag `P` till we reach first `F`)
	partialLines map[model.Fingerprint]Entry
	cfg          *CriConfig
	base         *Pipeline
	lock         sync.Mutex
}

// implement Stage interface
func (c *cri) Name() string {
	return "cri"
}

// Cleanup implements Stage.
func (*cri) Cleanup() {
	// no-op
}

// implements Stage interface
func (c *cri) Run(entry chan Entry) chan Entry {
	entry = c.base.Run(entry)

	in := RunWithSkipOrSendManyWithTick(entry, func(e Entry) ([]Entry, bool) {
		fingerprint := e.Labels.Fingerprint()

		// We received partial-line (tag: "P")
		if e.Extracted["flags"] == "P" {
			if len(c.partialLines) >= c.cfg.MaxPartialLines {
				// Merge existing partialLines
				entries := make([]Entry, 0, len(c.partialLines))
				for _, v := range c.partialLines {
					entries = append(entries, v)
				}

				level.Warn(c.base.logger).Log("msg", "cri stage: partial lines upperbound exceeded. merging it to single line", "threshold", c.cfg.MaxPartialLines)

				c.partialLines = make(map[model.Fingerprint]Entry, c.cfg.MaxPartialLines)
				c.ensureTruncateIfRequired(&e)
				c.partialLines[fingerprint] = e

				return entries, false
			}

			prev, ok := c.partialLines[fingerprint]
			if ok {
				var builder strings.Builder
				builder.WriteString(prev.Line)
				builder.WriteString(e.Line)
				e.Line = builder.String()
			}
			c.ensureTruncateIfRequired(&e)
			c.partialLines[fingerprint] = e

			return []Entry{e}, true // it's a partial-line so skip it.
		}

		// Now we got full-line (tag: "F").
		// 1. If any old partialLines matches with this full-line stream, merge it
		// 2. Else just return the full line.
		prev, ok := c.partialLines[fingerprint]
		if ok {
			var builder strings.Builder
			builder.WriteString(prev.Line)
			builder.WriteString(e.Line)
			e.Line = builder.String()
			c.ensureTruncateIfRequired(&e)
			delete(c.partialLines, fingerprint)
		}
		return []Entry{e}, false
	}, 10*time.Second, func() []Entry {
		// Send partial lines which are left unsent for a while.
		threshold := time.Now().Add(-c.cfg.MaxPartialLineAge)

		entries := make([]Entry, 0)
		fingerprints := make([]model.Fingerprint, 0)
		for k, v := range c.partialLines {
			if v.Timestamp.Before(threshold) {
				level.Warn(c.base.logger).Log("msg", "flushing partial line due to max age", "labels", v.Labels)
				entries = append(entries, v)
				fingerprints = append(fingerprints, k)
			}
		}
		for _, fp := range fingerprints {
			delete(c.partialLines, fp)
		}
		return entries
	})

	return in
}

func (c *cri) ensureTruncateIfRequired(e *Entry) {
	if c.cfg.MaxPartialLineSizeTruncate && len(e.Line) > c.cfg.MaxPartialLineSize.Val() {
		e.Line = e.Line[:c.cfg.MaxPartialLineSize.Val()]
	}
}

// CriConfig contains the configuration for the cri stage
type CriConfig struct {
	MaxPartialLines            int              `mapstructure:"max_partial_lines"`
	MaxPartialLineSize         flagext.ByteSize `mapstructure:"max_partial_line_size"`
	MaxPartialLineSizeTruncate bool             `mapstructure:"max_partial_line_size_truncate"`
	MaxPartialLineAge          time.Duration    `mapstructure:"max_partial_line_age"`
}

// validateCriConfig validates the CriConfig for the cri stage
func validateCriConfig(cfg *CriConfig) error {
	if cfg.MaxPartialLines == 0 {
		cfg.MaxPartialLines = MaxPartialLinesSize
	}
	if cfg.MaxPartialLineAge == time.Duration(0) {
		cfg.MaxPartialLineAge = DefaultMaxPartialLineAge
	}
	return nil
}

// NewCRI creates a CRI format specific pipeline stage
func NewCRI(logger log.Logger, config interface{}, registerer prometheus.Registerer) (Stage, error) {
	base := PipelineStages{
		PipelineStage{
			StageTypeRegex: RegexConfig{
				Expression: "^(?s)(?P<time>\\S+?) (?P<stream>stdout|stderr) (?P<flags>\\S+?) (?P<content>.*)$",
			},
		},
		PipelineStage{
			StageTypeLabel: LabelsConfig{
				"stream": nil,
			},
		},
		PipelineStage{
			StageTypeTimestamp: TimestampConfig{
				Source: "time",
				Format: RFC3339Nano,
			},
		},
		PipelineStage{
			StageTypeOutput: OutputConfig{
				"content",
			},
		},
		PipelineStage{
			StageTypeOutput: OutputConfig{
				"tags",
			},
		},
	}

	p, err := NewPipeline(logger, base, nil, registerer)
	if err != nil {
		return nil, err
	}

	cfg := &CriConfig{}
	if err := mapstructure.WeakDecode(config, cfg); err != nil {
		return nil, err
	}

	if err = validateCriConfig(cfg); err != nil {
		return nil, err
	}

	c := cri{
		cfg:  cfg,
		base: p,
	}
	c.partialLines = make(map[model.Fingerprint]Entry, c.cfg.MaxPartialLines)
	return &c, nil
}
