package report

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
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

		if filepath.Ext(entry.Name()) != ".json" {
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
		if files[i].ModTime.Equal(files[j].ModTime) {
			return files[i].Name < files[j].Name
		}
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

	for i := len(files) - 1; i >= 0; i-- {
		preferredPath := preferredPathFor(files[i].Path)
		info, err := os.Stat(preferredPath)
		if err == nil {
			return &ReportFileInfo{
				Name:    filepath.Base(preferredPath),
				Path:    preferredPath,
				Size:    info.Size(),
				ModTime: info.ModTime(),
			}, nil
		}
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

	if strings.TrimSpace(name) != "" {
		candidates := []string{
			filepath.Join(reportsDir, name),
		}

		if filepath.Ext(name) == "" {
			candidates = append(candidates, filepath.Join(reportsDir, name+".json"))
		}

		for _, candidate := range candidates {
			if _, err := os.Stat(candidate); err == nil {
				return preferredPathFor(candidate), nil
			}
		}

		return "", fmt.Errorf("report not found: %s", filepath.Join(reportsDir, name))
	}

	defaultPreferred := filepath.Join(reportsDir, "raw_report.json")
	if _, err := os.Stat(defaultPreferred); err == nil {
		return defaultPreferred, nil
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

	companion := companionReportPath(reportPath)
	if companion != "" {
		if _, err := os.Stat(companion); err == nil {
			_ = os.Remove(companion)
		}
		companionMD := CompanionMarkdownPath(companion)
		if _, err := os.Stat(companionMD); err == nil {
			_ = os.Remove(companionMD)
		}
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

func preferredPathFor(path string) string {
	if isRawReportPath(path) {
		enriched := enrichedPathFromRaw(path)
		if _, err := os.Stat(enriched); err == nil {
			return enriched
		}
	}
	return path
}

func companionReportPath(path string) string {
	if isRawReportPath(path) {
		enriched := enrichedPathFromRaw(path)
		if _, err := os.Stat(enriched); err == nil {
			return enriched
		}
		return ""
	}

	if isEnrichedReportPath(path) {
		raw := rawPathFromEnriched(path)
		if _, err := os.Stat(raw); err == nil {
			return raw
		}
	}

	return ""
}

func isRawReportPath(path string) bool {
	return strings.HasSuffix(strings.ToLower(path), "_raw.json")
}

func isEnrichedReportPath(path string) bool {
	lower := strings.ToLower(path)
	return strings.HasSuffix(lower, ".json") && !strings.HasSuffix(lower, "_raw.json")
}

func enrichedPathFromRaw(rawPath string) string {
	return strings.TrimSuffix(rawPath, "_raw.json") + ".json"
}

func rawPathFromEnriched(enrichedPath string) string {
	return strings.TrimSuffix(enrichedPath, ".json") + "_raw.json"
}
