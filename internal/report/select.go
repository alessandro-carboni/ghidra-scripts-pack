package report

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"
)

type ReportFileInfo struct {
	Name    string    `json:"name"`
	Path    string    `json:"path"`
	Size    int64     `json:"size"`
	ModTime time.Time `json:"mod_time"`
}

func ListReportInfos(reportsDir string) ([]ReportFileInfo, error) {
	entries, err := os.ReadDir(reportsDir)
	if err != nil {
		return nil, err
	}

	files := make([]ReportFileInfo, 0)
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		ext := filepath.Ext(entry.Name())
		if ext != ".json" {
			continue
		}

		fullPath := filepath.Join(reportsDir, entry.Name())
		info, err := entry.Info()
		if err != nil {
			return nil, err
		}

		files = append(files, ReportFileInfo{
			Name:    entry.Name(),
			Path:    fullPath,
			Size:    info.Size(),
			ModTime: info.ModTime(),
		})
	}

	sort.Slice(files, func(i, j int) bool {
		return files[i].ModTime.Before(files[j].ModTime)
	})

	return files, nil
}

func GetLastReportInfo(reportsDir string) (*ReportFileInfo, error) {
	files, err := ListReportInfos(reportsDir)
	if err != nil {
		return nil, err
	}
	if len(files) == 0 {
		return nil, nil
	}
	last := files[len(files)-1]
	return &last, nil
}

func ResolveReportPath(reportsDir string, name string, last bool) (string, error) {
	if last {
		info, err := GetLastReportInfo(reportsDir)
		if err != nil {
			return "", err
		}
		if info == nil {
			return "", fmt.Errorf("no report files found in %s", reportsDir)
		}
		return info.Path, nil
	}

	if name != "" {
		fullPath := filepath.Join(reportsDir, name)
		if _, err := os.Stat(fullPath); err != nil {
			return "", fmt.Errorf("report not found: %s", fullPath)
		}
		return fullPath, nil
	}

	defaultPath := filepath.Join(reportsDir, "raw_report.json")
	if _, err := os.Stat(defaultPath); err == nil {
		return defaultPath, nil
	}

	info, err := GetLastReportInfo(reportsDir)
	if err != nil {
		return "", err
	}
	if info != nil {
		return info.Path, nil
	}

	return "", fmt.Errorf("no report found")
}

func CompanionMarkdownPath(reportPath string) string {
	return reportPath[:len(reportPath)-len(filepath.Ext(reportPath))] + ".md"
}

func DeleteReportWithMarkdown(reportPath string) error {
	if err := os.Remove(reportPath); err != nil {
		return err
	}

	mdPath := CompanionMarkdownPath(reportPath)
	if _, err := os.Stat(mdPath); err == nil {
		_ = os.Remove(mdPath)
	}

	return nil
}

func DeleteAllReportsWithMarkdown(reportsDir string) error {
	entries, err := os.ReadDir(reportsDir)
	if err != nil {
		return err
	}

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		ext := filepath.Ext(entry.Name())
		if ext != ".json" && ext != ".md" {
			continue
		}

		fullPath := filepath.Join(reportsDir, entry.Name())
		_ = os.Remove(fullPath)
	}

	return nil
}