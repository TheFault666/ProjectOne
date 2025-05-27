// Author: D-Fault(www.github.com/TheFault666)
package audit

import (
	"fmt"
	"time"

	"github.com/jung-kurt/gofpdf"
)

// addWatermark draws a semi-transparent rotated text watermark on the page
func addWatermark(pdf *gofpdf.Fpdf, text string) {
	pdf.SetFont("Arial", "B", 50)
	pdf.SetTextColor(200, 200, 200) // Light gray
	pdf.SetAlpha(0.2, "Normal")     // 20% opacity
	pdf.TransformBegin()
	pdf.TransformRotate(45, 105, 105) // Rotate around approx center of page
	pdf.Text(20, 110, text)
	pdf.TransformEnd()
	pdf.SetAlpha(1.0, "Normal") // Reset opacity

	// Reset font and color for normal content after watermark
	pdf.SetFont("Arial", "", 12)
	pdf.SetTextColor(0, 0, 0)
}

func GeneratePDFReport(
	ip string,
	systemInfo, osDetails, userDetails, networkDetails, usbStatus, bitLocker, biosDetails, secureBoot, antivirus, firewall, pirated, updates, outdated string,
	startTime time.Time,
) error {
	filename := fmt.Sprintf("%s_Security_Audit_Report.pdf", ip)
	pdf := gofpdf.New("P", "mm", "A4", "")
	pdf.SetTitle("Windows Security Audit Report", false)

	// Add watermark on every page automatically
	pdf.SetHeaderFunc(func() {
		addWatermark(pdf, "D-Fault")
	})

	pdf.AddPage()

	pdf.SetFont("Arial", "B", 16)
	pdf.Cell(0, 10, "Windows Security Audit Report")
	pdf.Ln(12)

	pdf.SetFont("Arial", "", 12)
	pdf.Cell(0, 8, fmt.Sprintf("Scan started: %s", startTime.Format(time.RFC1123)))
	pdf.Ln(10)

	writeSection := func(title, content string) {
		pdf.SetFont("Arial", "B", 14)
		pdf.Cell(0, 8, title)
		pdf.Ln(7)
		pdf.SetFont("Arial", "", 11)
		pdf.MultiCell(0, 6, content, "", "", false)
		pdf.Ln(6)
	}

	writeSection("Complete System Details:", systemInfo)
	writeSection("OS Details:", osDetails)
	writeSection("User Details:", userDetails)
	writeSection("Network Details:", networkDetails)
	writeSection("USB Storage Access:", usbStatus)
	writeSection("BitLocker Details:", bitLocker)
	writeSection("BIOS Details:", biosDetails)
	writeSection("Secure Boot Status:", secureBoot)
	writeSection("Antivirus Details:", antivirus)
	writeSection("Firewall Details:", firewall)
	writeSection("Pirated Software Scan:", pirated)
	writeSection("Available Software Updates:", updates)
	writeSection("Outdated Softwares:", outdated)

	err := pdf.OutputFileAndClose(filename)
	if err != nil {
		return fmt.Errorf("error writing PDF file: %w", err)
	}
	return nil
}

//Author: D-Fault(www.github.com/TheFault666)
