package tui

import (
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/mbergz/go-certviewer/internal/model"

	"github.com/atotto/clipboard"
	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"
)

var (
	app          *tview.Application
	mainFlex     *tview.Flex
	mouseEnabled bool = true
	views        []View
)

func Launch(certCollection model.CertificateCollection) {
	app = tview.NewApplication()
	app.EnableMouse(mouseEnabled)

	app.SetInputCapture(func(event *tcell.EventKey) *tcell.EventKey {
		if event.Rune() == 'm' {
			mouseEnabled = !mouseEnabled
			app.EnableMouse(mouseEnabled)
		}
		return event
	})

	subjectView := newSubjectView()
	issuerView := newIssuerView()
	extensionsView := newExtensionsView()
	publicKeyView := newPublicKeyView()
	signatureView := newSignatureView()
	validityView := newValidityView()
	fingerprintView := newFingerprintView()
	views = append(views, subjectView, issuerView, extensionsView, publicKeyView, signatureView, validityView, fingerprintView)

	populateCertColorMap(certCollection)

	certInfoArea := createCertInfoArea(certCollection, onSelectedCert)

	mainFlex = tview.NewFlex().
		AddItem(tview.NewFlex().SetDirection(tview.FlexRow).
			AddItem(tview.NewFlex().SetDirection(tview.FlexColumn).
				AddItem(subjectView.primitive(), 0, 4, false).
				AddItem(issuerView.primitive(), 0, 3, false), 0, 3, false).
			AddItem(validityView.primitive(), 0, 2, false).
			AddItem(extensionsView.primitive(), 0, 4, false).
			AddItem(tview.NewFlex().SetDirection(tview.FlexColumn).
				AddItem(publicKeyView.primitive(), 0, 1, false).
				AddItem(signatureView.primitive(), 0, 1, false), 0, 2, false).
			AddItem(fingerprintView.primitive(), 0, 1, false),
			0, 4, false).
		AddItem(certInfoArea, 0, 1, true)

	if err := app.SetRoot(mainFlex, true).SetFocus(mainFlex).Run(); err != nil {
		panic(err)
	}
}

func onSelectedCert(cert *x509.Certificate) func() {
	return func() {
		for _, v := range views {
			v.update(cert)
		}
	}
}

func appendToTableKeyOnly(table *tview.Table, displayName string, rowCount *int) {
	table.SetCell(*rowCount, 0, tview.NewTableCell("[#bdbdbd]"+fmt.Sprintf("%-25s", displayName)).SetSelectable(true).SetTransparency(true))
	*rowCount++
}

func appendToTable(table *tview.Table, value []string, displayName string, rowCount *int) {
	appendToTableTitleWidth(table, value, displayName, 25, rowCount)
}

func appendToTableTitleWidth(table *tview.Table, value []string, displayName string, displayNameWidth int, rowCount *int) {
	if len(value) == 0 {
		return
	}

	displayNameFormat := fmt.Sprintf("%%-%ds", displayNameWidth)
	table.SetCell(*rowCount, 0, tview.NewTableCell("[#bdbdbd]"+fmt.Sprintf(displayNameFormat, displayName)).SetSelectable(true).SetTransparency(true))
	table.SetCell(*rowCount, 1, tview.NewTableCell(strings.Join(value, ",")).SetSelectable(true).SetClickedFunc(func() bool {
		displayText := strings.Join(value, ",")

		darkGray := tcell.NewRGBColor(40, 40, 40)
		fullTextView := tview.NewTextView()
		fullTextView.SetText(displayText)
		fullTextView.SetBackgroundColor(darkGray)

		fullTextView.SetMouseCapture(func(action tview.MouseAction, event *tcell.EventMouse) (tview.MouseAction, *tcell.EventMouse) {
			if action == tview.MouseRightClick {
				content := fullTextView.GetText(true)
				clipboard.WriteAll(content)
			}
			return action, event
		})

		okBtn := tview.NewButton("OK").SetSelectedFunc(func() {
			app.SetRoot(mainFlex, true)
		})

		okBtnFlex := tview.NewFlex().SetDirection(tview.FlexColumn).
			AddItem(tview.NewBox().SetBackgroundColor(darkGray), 0, 1, false).
			AddItem(okBtn, 8, 1, false).
			AddItem(tview.NewBox().SetBackgroundColor(darkGray), 0, 1, false)

		fullTextViewWrapper := tview.NewFlex().SetDirection(tview.FlexRow).
			AddItem(fullTextView, 0, 3, false).
			AddItem(okBtnFlex, 1, 1, false)
		fullTextViewWrapper.SetBorder(true)
		fullTextViewWrapper.SetBackgroundColor(darkGray)

		vertFlexSize := 1
		if len(strings.Join(value, ",")) > 200 {
			vertFlexSize = 2
		}
		vertFlex := tview.NewFlex().SetDirection(tview.FlexRow).
			AddItem(nil, 0, 2, false).
			AddItem(fullTextViewWrapper, 0, vertFlexSize, false).
			AddItem(nil, 0, 2, false)

		modalFlex := tview.NewFlex().
			AddItem(nil, 0, 1, false).
			AddItem(vertFlex, 0, 2, true).
			AddItem(nil, 0, 1, false)

		modalFlex.SetInputCapture(func(event *tcell.EventKey) *tcell.EventKey {
			if event.Key() == tcell.KeyESC {
				app.SetRoot(mainFlex, true)
			}
			return event
		})

		pages := tview.NewPages().
			AddPage("mainFlex", mainFlex, false, true).
			AddPage("modal", modalFlex, true, true)
		app.SetRoot(pages, true)
		return true
	}))
	*rowCount++
}

func formatToHex(input []byte) string {
	return formatHexStr(hex.EncodeToString(input))
}

func formatHexStr(hexInput string) string {
	var builder strings.Builder

	if len(hexInput)%2 == 1 {
		hexInput = "0" + hexInput
	}

	for i, r := range strings.ToUpper(hexInput) {
		builder.WriteRune(r)
		if i%2 == 1 {
			builder.WriteRune(' ')
		}
	}
	return builder.String()
}
