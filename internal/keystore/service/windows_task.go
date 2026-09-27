package service

func renderScheduledTaskCommand(executable, trustFile string) string {
	command := quoteWindowsArgument(executable) + " --app-service"
	if trustFile != "" {
		command += " --key-transparency-trust-file " + quoteWindowsArgument(trustFile)
	}
	return command
}

func quoteWindowsArgument(value string) string {
	return `"` + value + `"`
}
