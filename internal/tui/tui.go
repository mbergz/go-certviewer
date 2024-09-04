package tui

import (
	"crypto/x509"
	"fmt"

	"github.com/rivo/tview"
)

var (
	app *tview.Application
)

func createCertChainList(certs []*x509.Certificate) *tview.List {
	certChainList := tview.NewList()
	certChainList.SetBorder(true).SetTitle("Certificate chain")

	for i, cert := range certs {
		text := fmt.Sprintf("Cert %d, CN=%s", i+1, cert.Subject.CommonName)
		certChainList.AddItem(text, "", 0, func() {
			// TODO
		})
	}
	return certChainList
}

func createCenteredTableFlex(certs []*x509.Certificate) *tview.Flex {
	generalTable := tview.NewTable()

	cols := 2
	rows := 3
	for i := 0; i < rows; i++ {
		for j := 0; j < cols; j++ {
			generalTable.SetCell(i, j,
				tview.NewTableCell(fmt.Sprintf("Row: %d, Cell: %d", i, j)).SetAlign(tview.AlignCenter))
		}
	}

	centeredTable := tview.NewFlex().AddItem(tview.NewBox(), 0, 1, false).
		AddItem(generalTable, 0, 2, false).
		AddItem(tview.NewBox(), 0, 1, false).SetDirection(tview.FlexColumn)

	return centeredTable
}

func Launch(certs []*x509.Certificate) {
	app = tview.NewApplication()

	certChainList := createCertChainList(certs)

	topTextField := tview.NewTextView().SetText("OK").SetTextAlign(tview.AlignCenter)

	generalFlex := tview.NewFlex().SetDirection(tview.FlexRow)
	generalFlex.SetBorder(true).SetTitle("General")

	centeredTable := createCenteredTableFlex(certs)
	generalFlex.AddItem(topTextField, 0, 1, false).AddItem(centeredTable, 0, 1, false)

	mainFlex := tview.NewFlex().
		AddItem(tview.NewFlex().SetDirection(tview.FlexRow).
			AddItem(generalFlex, 0, 2, false).
			AddItem(tview.NewBox().SetBorder(true).SetTitle("Validity"), 0, 1, false).
			AddItem(tview.NewBox().SetBorder(true).SetTitle("Signature"), 10, 1, false), 0, 2, false).
		AddItem(certChainList, 30, 1, true)

	if err := app.SetRoot(mainFlex, true).SetFocus(mainFlex).Run(); err != nil {
		panic(err)
	}
}
