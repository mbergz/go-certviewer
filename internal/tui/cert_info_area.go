package tui

import (
	"crypto/x509"
	"fmt"

	"github.com/mbergz/go-certviewer/internal/model"
	"github.com/rivo/tview"
)

func createCertInfoArea(certCollection model.CertificateCollection, onSelectedCert func(cert *x509.Certificate) func()) tview.Primitive {
	certChainList := createCertChainList(certCollection, onSelectedCert)
	var allCerts *tview.List
	if len(certCollection.All) > 0 {
		allCerts = createAllCertsList(certCollection, onSelectedCert)
	}

	if allCerts != nil {
		return tview.NewFlex().SetDirection(tview.FlexRow).
			AddItem(certChainList, 0, 1, true).
			AddItem(allCerts, 0, 1, false)
	}
	return certChainList
}

func createCertChainList(certCollection model.CertificateCollection, onSelectedCert func(cert *x509.Certificate) func()) *tview.List {
	certChainList := tview.NewList()
	title := "Certificate chain"
	if len(certCollection.Chains) > 1 {
		title += "s"
	}
	certChainList.SetBorder(true).SetTitle(title)

	for i, chain := range certCollection.Chains {
		for _, cert := range chain {
			text := fmt.Sprintf("%d: CN=%s", cert.Index, colorizeCommonName(cert.Cert, false))
			certChainList.AddItem(text, "", 0, onSelectedCert(cert.Cert))
		}
		if i != len(certCollection.Chains)-1 {
			certChainList.AddItem("-----Next chain------", "", 0, nil)
		}
	}

	onSelectedCert(certCollection.Chains[0][0].Cert)()
	return certChainList
}

func createAllCertsList(certCollection model.CertificateCollection, onSelectedCert func(cert *x509.Certificate) func()) *tview.List {
	allCertsList := tview.NewList().SetSelectedFocusOnly(true)
	allCertsList.SetBorder(true).SetTitle("All certificates")

	// Only render grouped by filename if all certs have a filename set
	haveFileNames := true
	for _, cert := range certCollection.All {
		if cert.FileName == "" {
			haveFileNames = false
			break
		}
	}

	if haveFileNames {
		fileNameCertsMap := make(map[string][]model.CertificateEntry)
		for _, cert := range certCollection.All {
			if found, ok := fileNameCertsMap[cert.FileName]; ok {
				fileNameCertsMap[cert.FileName] = append(found, cert)
			} else {
				fileNameCertsMap[cert.FileName] = []model.CertificateEntry{cert}
			}
		}

		for key, value := range fileNameCertsMap {
			allCertsList.AddItem(fmt.Sprintf("-- %s --", key), "", 0, nil)
			addCertsToAllList(allCertsList, value, onSelectedCert)
		}
	} else {
		addCertsToAllList(allCertsList, certCollection.All, onSelectedCert)
	}

	return allCertsList
}

func addCertsToAllList(list *tview.List, certs []model.CertificateEntry, onSelectedCert func(cert *x509.Certificate) func()) {
	for _, cert := range certs {
		text := fmt.Sprintf("%d: CN=%s", cert.Index, colorizeCommonName(cert.Cert, false))
		list.AddItem(text, "", 0, onSelectedCert(cert.Cert))
	}
}
