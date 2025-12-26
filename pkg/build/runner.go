package build

// Runner represents a container runner type.
type Runner string

const (
	// RunnerDocker is the Docker-based container runner.
	// This is the only supported runner for the test command.
	RunnerDocker Runner = "docker"
)

// GetAllRunners returns a list of all valid runners.
func GetAllRunners() []Runner {
	return []Runner{
		RunnerDocker,
	}
}
