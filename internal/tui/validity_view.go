package tui

import (
	"crypto/x509"
	"fmt"
	"time"

	"github.com/rivo/tview"
)

type ValidityView struct {
	validityFlex    *tview.Flex
	validityTable   *tview.Table
	validtyTextView *tview.TextView
}

func newValidityView() *ValidityView {
	validityFlex := tview.NewFlex().SetDirection(tview.FlexRow)
	validityFlex.SetBorder(true).SetTitle("Validity")

	validityTable := tview.NewTable()
	validityTable.SetBorderPadding(1, 0, 0, 0)

	validtyTextView := tview.NewTextView().SetTextAlign(tview.AlignCenter).SetDynamicColors(true)
	validityFlex.AddItem(validityTable, 0, 5, false).AddItem(validtyTextView, 0, 1, false)

	return &ValidityView{validityFlex, validityTable, validtyTextView}
}

func (v *ValidityView) primitive() tview.Primitive {
	return v.validityFlex
}

func (v *ValidityView) update(cert *x509.Certificate) {
	row := 0
	appendToTable(v.validityTable, []string{cert.NotBefore.String()}, "Valid From", &row)
	appendToTable(v.validityTable, []string{cert.NotAfter.String()}, "Valid To", &row)
	v.validtyTextView.Clear()

	now := time.Now()
	if now.After(cert.NotAfter) {
		fmt.Fprintf(v.validtyTextView, "Certificate has [red]expired[white]")
	} else {
		expiresIn := cert.NotAfter.Sub(now)
		expiresInDays := int(expiresIn.Hours() / 24)

		if expiresInDays > 30 {
			fmt.Fprintf(v.validtyTextView, "Certificate will expire in [green]%d[white] days", expiresInDays)
		} else if expiresInDays < 3 {
			fmt.Fprintf(v.validtyTextView, "Certificate will expire in [red]%d[white] days", expiresInDays)
		} else if expiresInDays < 10 {
			fmt.Fprintf(v.validtyTextView, "Certificate will expire in [orange]%d[white] days", expiresInDays)
		} else { // 10 - 30 days
			fmt.Fprintf(v.validtyTextView, "Certificate will expire in [yellow]%d[white] days", expiresInDays)
		}
	}
}
