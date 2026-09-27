//go:build darwin

package service

import (
	"bytes"
	"encoding/xml"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
)

const launchAgentLabel = "io.dragpass.keeper.app-service"

func manageLinux(string, string) error {
	return errors.New("Keeper App service lifecycle is not supported on this operating system")
}

func manageWindows(string, string) error {
	return errors.New("Keeper App service lifecycle is not supported on this operating system")
}

type launchAgent struct {
	XMLName    xml.Name  `xml:"plist"`
	Version    string    `xml:"version,attr"`
	Dictionary agentDict `xml:"dict"`
}

type agentDict struct {
	Label             string
	ProgramArguments  []string
	StandardOutPath   string
	StandardErrorPath string
	TrustFilePath     string
}

func (d agentDict) MarshalXML(encoder *xml.Encoder, start xml.StartElement) error {
	if err := encoder.EncodeToken(start); err != nil {
		return err
	}
	if err := plistString(encoder, "Label", d.Label); err != nil {
		return err
	}
	if err := encoder.EncodeToken(xml.StartElement{Name: xml.Name{Local: "key"}}); err != nil {
		return err
	}
	if err := encoder.EncodeToken(xml.CharData("ProgramArguments")); err != nil {
		return err
	}
	if err := encoder.EncodeToken(xml.EndElement{Name: xml.Name{Local: "key"}}); err != nil {
		return err
	}
	if err := encoder.EncodeToken(xml.StartElement{Name: xml.Name{Local: "array"}}); err != nil {
		return err
	}
	for _, argument := range d.ProgramArguments {
		if err := encoder.EncodeElement(argument, xml.StartElement{Name: xml.Name{Local: "string"}}); err != nil {
			return err
		}
	}
	if err := encoder.EncodeToken(xml.EndElement{Name: xml.Name{Local: "array"}}); err != nil {
		return err
	}
	if d.TrustFilePath != "" {
		if err := encoder.EncodeElement("EnvironmentVariables", xml.StartElement{Name: xml.Name{Local: "key"}}); err != nil {
			return err
		}
		if err := encoder.EncodeToken(xml.StartElement{Name: xml.Name{Local: "dict"}}); err != nil {
			return err
		}
		if err := plistString(encoder, "DRAGPASS_KEY_TRANSPARENCY_TRUST_FILE", d.TrustFilePath); err != nil {
			return err
		}
		if err := encoder.EncodeToken(xml.EndElement{Name: xml.Name{Local: "dict"}}); err != nil {
			return err
		}
	}
	for _, item := range []struct{ key, value string }{
		{"RunAtLoad", ""}, {"KeepAlive", ""},
		{"StandardOutPath", d.StandardOutPath}, {"StandardErrorPath", d.StandardErrorPath},
	} {
		if err := encoder.EncodeElement(item.key, xml.StartElement{Name: xml.Name{Local: "key"}}); err != nil {
			return err
		}
		if item.value == "" {
			if err := encoder.EncodeToken(xml.StartElement{Name: xml.Name{Local: "true"}}); err != nil {
				return err
			}
			if err := encoder.EncodeToken(xml.EndElement{Name: xml.Name{Local: "true"}}); err != nil {
				return err
			}
		} else if err := encoder.EncodeElement(item.value, xml.StartElement{Name: xml.Name{Local: "string"}}); err != nil {
			return err
		}
	}
	return encoder.EncodeToken(start.End())
}

func plistString(encoder *xml.Encoder, key, value string) error {
	if err := encoder.EncodeElement(key, xml.StartElement{Name: xml.Name{Local: "key"}}); err != nil {
		return err
	}
	return encoder.EncodeElement(value, xml.StartElement{Name: xml.Name{Local: "string"}})
}

func manageDarwin(action, invokedPath string) error {
	currentUser, err := user.Current()
	if err != nil {
		return errors.New("could not determine the current macOS user")
	}
	uid, err := strconv.Atoi(currentUser.Uid)
	if err != nil || uid == 0 {
		return errors.New("service commands must run in a logged-in user session")
	}
	domain := fmt.Sprintf("gui/%d", uid)
	plistPath := filepath.Join(currentUser.HomeDir, "Library", "LaunchAgents", launchAgentLabel+".plist")
	if action == "uninstall" {
		_ = exec.Command("launchctl", "bootout", domain+"/"+launchAgentLabel).Run()
		if err := os.Remove(plistPath); err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("remove Keeper LaunchAgent: %w", err)
		}
		return nil
	}

	executable := invokedPath
	if strings.Contains(executable, "/Caskroom/") || strings.Contains(executable, "/Cellar/") {
		if stablePath, lookupErr := exec.LookPath("dragpass-keeper"); lookupErr == nil {
			executable = stablePath
		}
	} else if !filepath.IsAbs(executable) {
		executable, err = exec.LookPath("dragpass-keeper")
		if err != nil {
			executable, err = filepath.Abs(invokedPath)
		}
	}
	if err != nil {
		return errors.New("could not resolve the Keeper executable path")
	}
	if !filepath.IsAbs(executable) {
		executable, err = filepath.Abs(executable)
		if err != nil {
			return errors.New("could not resolve the Keeper executable path")
		}
	}
	logDir := filepath.Join(currentUser.HomeDir, "Library", "Logs", "DragPass")
	if err := os.MkdirAll(filepath.Dir(plistPath), 0o700); err != nil {
		return fmt.Errorf("create LaunchAgents directory: %w", err)
	}
	if err := os.MkdirAll(logDir, 0o700); err != nil {
		return fmt.Errorf("create Keeper log directory: %w", err)
	}
	trustFile, err := configuredTrustFile()
	if err != nil {
		return err
	}
	content, err := marshalLaunchAgent(executable, filepath.Join(logDir, "app-service.log"), trustFile)
	if err != nil {
		return fmt.Errorf("encode Keeper LaunchAgent: %w", err)
	}
	tempFile, err := os.CreateTemp(filepath.Dir(plistPath), ".keeper-agent-*.plist")
	if err != nil {
		return fmt.Errorf("create temporary LaunchAgent: %w", err)
	}
	tempPath := tempFile.Name()
	defer os.Remove(tempPath)
	if err := tempFile.Chmod(0o600); err != nil {
		tempFile.Close()
		return fmt.Errorf("secure temporary LaunchAgent: %w", err)
	}
	if _, err := tempFile.Write(content); err != nil {
		tempFile.Close()
		return fmt.Errorf("write Keeper LaunchAgent: %w", err)
	}
	if err := tempFile.Close(); err != nil {
		return fmt.Errorf("close Keeper LaunchAgent: %w", err)
	}
	if err := os.Rename(tempPath, plistPath); err != nil {
		return fmt.Errorf("install Keeper LaunchAgent: %w", err)
	}
	_ = exec.Command("launchctl", "bootout", domain+"/"+launchAgentLabel).Run()
	if output, err := exec.Command("launchctl", "bootstrap", domain, plistPath).CombinedOutput(); err != nil {
		return fmt.Errorf("start Keeper App service: %s", strings.TrimSpace(string(output)))
	}
	return nil
}

func marshalLaunchAgent(executable, logPath, trustFile string) ([]byte, error) {
	manifest := launchAgent{Version: "1.0", Dictionary: agentDict{
		Label:             launchAgentLabel,
		ProgramArguments:  []string{executable, "--app-service"},
		StandardOutPath:   logPath,
		StandardErrorPath: logPath,
		TrustFilePath:     trustFile,
	}}
	var content bytes.Buffer
	content.WriteString(xml.Header)
	encoder := xml.NewEncoder(&content)
	encoder.Indent("", "  ")
	if err := encoder.Encode(manifest); err != nil {
		return nil, err
	}
	content.WriteByte('\n')
	return content.Bytes(), nil
}
