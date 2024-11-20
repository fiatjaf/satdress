package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/fiatjaf/go-lnurl"
	"github.com/gorilla/mux"
	"github.com/nbd-wtf/go-nostr"
	decodepay "github.com/nbd-wtf/ln-decodepay"
)

var allowNostr bool = false
var nostrPrivkeyHex string = ""
var nostrPubkey string = ""
var minSendable int = 1000
var maxSendable int = 1000000000
var CommentAllowed int = 2000

type LNURLPayParamsCustom struct {
	lnurl.LNURLResponse
	Callback        string               `json:"callback"`
	Tag             string               `json:"tag"`
	MaxSendable     int64                `json:"maxSendable"`
	MinSendable     int64                `json:"minSendable"`
	EncodedMetadata string               `json:"metadata"`
	CommentAllowed  int64                `json:"commentAllowed"`
	PayerData       *lnurl.PayerDataSpec `json:"payerData,omitempty"`
	AllowsNostr     bool                 `json:"allowsNostr,omitempty"`
	NostrPubKey     string               `json:"nostrPubkey,omitempty"`
	Metadata        lnurl.Metadata       `json:"-"`
}

type LNURLPayValuesCustom struct {
	lnurl.LNURLResponse
	SuccessAction      *lnurl.SuccessAction `json:"successAction"`
	Routes             interface{}          `json:"routes"` // ignored
	PR                 string               `json:"pr"`
	Disposable         *bool                `json:"disposable,omitempty"`
	Comment            string               `json:"comment"`
	CreatedAt          time.Time            `json:"created_at"`
	Paid               bool                 `json:"paid"`
	PaidAt             time.Time            `json:"paid_at"`
	From               string               `json:"from"`
	ParsedInvoice      decodepay.Bolt11     `json:"-"`
	PayerDataJSON      string               `json:"-"`
	Nip57Receipt       nostr.Event          `json:"nip57Receipt"`
	Nip57ReceiptRelays []string             `json:"nip57ReceiptRelays"`
	AwaitInvoicePaid   bool                 `json:"awaitInvoicePaid"`
	Sender             string               `json:"sender"`
	Note               string               `json:"note"`
}

func handleLNURL(w http.ResponseWriter, r *http.Request) {
	var err error
	var response interface{}

	username := mux.Vars(r)["user"]
	domains := getDomains(s.Domain)
	domain := ""

	if len(domains) == 1 {
		domain = domains[0]
	} else {
		hostname := r.URL.Host
		if hostname == "" {
			hostname = r.Host
		}

		for _, one := range getDomains(s.Domain) {
			if strings.Contains(hostname, one) {
				domain = one
				break
			}
		}
		if domain == "" {
			json.NewEncoder(w).Encode(lnurl.ErrorResponse("incorrect domain"))
			return
		}
	}

	params, err := GetName(username, domain)
	if err != nil {
		log.Error().Err(err).Str("name", username).Str("domain", domain).Msg("failed to get name")
		json.NewEncoder(w).Encode(lnurl.ErrorResponse(fmt.Sprintf(
			"failed to get name %s@%s", username, domain)))
		return
	}

	//if account is a forward account we simply redirect to the other address.
	//everything is handled from there. In this case, we only provide Address/NIP05
	if params.Kind == "forward" {
		http.Redirect(w, r, params.Host, http.StatusSeeOther)
		return
	}

	log.Debug().Str("username", username).Str("domain", domain).Msg("got lnurl request")

	if amount := r.URL.Query().Get("amount"); amount == "" {
		// convert configured sendable amounts to integer
		minSendable, err := strconv.ParseInt(params.MinSendable, 10, 64)
		// set defaults
		if err != nil {
			minSendable = 1000
		}
		maxSendable, err := strconv.ParseInt(params.MaxSendable, 10, 64)
		if err != nil {
			maxSendable = 1000000000
		}

		json.NewEncoder(w).Encode(lnurl.LNURLPayParams{
			LNURLResponse:   lnurl.LNURLResponse{Status: "OK"},
			Callback:        fmt.Sprintf("https://%s/.well-known/lnurlp/%s", domain, username),
			MinSendable:     minSendable,
			MaxSendable:     maxSendable,
			EncodedMetadata: metaData(params).Encode(),
			CommentAllowed:  int64(CommentAllowed),
			Tag:             "payRequest",
			AllowsNostr:     allowNostr,
			NostrPubKey:     nostrPubkey,
		})

	} else {

		msat, err := strconv.Atoi(amount)
		if err != nil {
			json.NewEncoder(w).Encode(lnurl.ErrorResponse("amount is not integer"))
			return
		}

		var comment = ""
		var payerData lnurl.PayerDataValues
		// nostr NIP-57
		// the "nostr" query param has a zap request which is a nostr event
		// that specifies which nostr note has been zapped.
		// here we check wheter its present, the event signature is valid
		// and whether the event has the necessary tags that we need (p and relays are necessary, e is optional)

		zapEventQuery := r.FormValue("nostr")
		var zapEvent nostr.Event
		if len(zapEventQuery) > 0 {
			err = json.Unmarshal([]byte(zapEventQuery), &zapEvent)
			if err != nil {
				log.Error().Err(err).Str("Couldn't parse nostr event: ", err.Error())
			} else {
				valid, err := zapEvent.CheckSignature()
				if !valid || err != nil {
					log.Error().Err(err).Str("Nostr NIP-57 zap event signature invalid: ", err.Error())
					return
				}
				if len(zapEvent.Tags) == 0 || zapEvent.Tags.GetFirst([]string{"p"}) == nil {
					log.Error().Err(err).Str("Nostr NIP-57 zap event validation error ", "")
					return
				}
			}
			if len(zapEvent.Content) > 0 {
				comment = zapEvent.Content
				log.Debug().Str("NIP57 Comment received", comment).Msg("Comment")
			}

		}
		//We can't handle comments and payerdata in NIP57 at the same time...

		// If a comment is send with the Invoice, always use it (?)
		regularcomment := r.FormValue("comment")
		if len(regularcomment) > CommentAllowed {
			log.Error().Err(err).Str("Comment is too long", err.Error())
			return
		}
		if len(regularcomment) > 0 {
			comment = regularcomment
			log.Debug().Str("Comment received", comment).Msg("Comment")
		}
		// payer data, not used currently
		payerdata := r.FormValue("payerdata")

		if len(payerdata) > 0 {
			err = json.Unmarshal([]byte(payerdata), &payerData)
			if err != nil {
				log.Error().Err(err).Str("Couldn't parse payerdata", err.Error())
			}
		}

		//we outsource the second part in a function, we should do this for the first one too.
		response, err = serveLNURLpSecond(w, params, username, msat, comment, payerData, zapEvent)
		var payvaluescustom = response.(LNURLPayValuesCustom)
		if err != nil {
			// there is a valid error response
			json.NewEncoder(w).Encode(response)
			return
		}

		json.NewEncoder(w).Encode(lnurl.LNURLPayValues{
			LNURLResponse: lnurl.LNURLResponse{Status: "OK"},
			PR:            bolt11,
			Routes:        make([]interface{}, 0),
			Disposable:    lnurl.FALSE,
			SuccessAction: lnurl.Action("Payment received!", ""),
		})

		//if we provided a nsec and the response contained zap information, we wait for the invoice to be paid
		//in order to submit the zap on nostr
		//also check for invoice paid for regular ln payments for nostr notificaitons
		if payvaluescustom.AwaitInvoicePaid {
			go WaitForInvoicePaid(payvaluescustom, params)
		}
	}
}

func serveLNURLpSecond(w http.ResponseWriter, params *Params, username string, amount_msat int, comment string, payerData lnurl.PayerDataValues, zapEvent nostr.Event) (LNURLPayValuesCustom, error) {
	log.Debug().Any("Serving invoice for user %s", username)
	if amount_msat < minSendable || amount_msat > maxSendable {
		// amount is not ok
		return LNURLPayValuesCustom{
			LNURLResponse: lnurl.LNURLResponse{
				Status: "Error",
				Reason: fmt.Sprintf("Amount out of bounds (min: %d sat, max: %d sat).", minSendable/1000, maxSendable/1000)},
		}, fmt.Errorf("amount out of bounds")
	}

	// NIP57 ZAPs
	// for nip57 use the nostr event as the descriptionHash
	if zapEvent.Sig != "" {

		// we calculate the descriptionHash here, create an invoice with it
		// and store the invoice in the zap receipt later down the line
		zapEventSerialized, err := json.Marshal(zapEvent)
		zapEventSerializedStr = fmt.Sprintf("%s", zapEventSerialized)
		if err != nil {
			return LNURLPayValuesCustom{
				LNURLResponse: lnurl.LNURLResponse{
					Status: "Error",
					Reason: "Couldn't serialize zap event."},
			}, err
		}
		// we extract the relays from the zap request
		nip57ReceiptRelays = ExtractNostrRelays(zapEvent)

	} else {
		//If we have a regular call, we ignore zapEvent in makeinvoice later.
		zapEventSerializedStr = ""
		log.Debug().Str("Regular Invoice", "Not an NIP57 event").Msg("Note")
	}

	var response LNURLPayValuesCustom
	invoice, err := makeInvoice(params, amount_msat, nil, zapEventSerializedStr, comment)
	if err != nil {
		err = fmt.Errorf("couldn't create invoice: %v", err.Error())
		response = LNURLPayValuesCustom{
			LNURLResponse: lnurl.LNURLResponse{
				Status: "Error",
				Reason: "Couldn't create invoice."},
		}
		return response, err
	}

	//Check invoice paid only if we actually have a NIP57 event
	var awaitPaid = true
	var sender = ""
	var note = ""
	// nip57 - we need to store the newly created invoice in the zap receipt
	if zapEvent.Sig != "" {
		// TODO: Handle the err
		nip57Receipt, err = CreateNostrReceipt(zapEvent, invoice)
		sender = "@" + EncodeBech32Public(zapEvent.PubKey)
		if zapEvent.Tags.GetFirst([]string{"e"}) != nil {
			note = "@" + EncodeBech32Note(zapEvent.Tags.GetFirst([]string{"e"}).Value())
		}
		if zapEvent.Tags.GetFirst([]string{"anon"}) != nil {
			if zapEvent.Tags.GetFirst([]string{"anon"}).Value() == "" {
				sender = "anonymous Zapper 🤙"
			}
		}
		log.Debug().Str("Zap from", sender).Msg("Nostr")
	}

	decoded_invoice, _ := decodepay.Decodepay(invoice)
	return LNURLPayValuesCustom{
		LNURLResponse:      lnurl.LNURLResponse{Status: "OK"},
		PR:                 invoice,
		Routes:             make([]struct{}, 0),
		SuccessAction:      &lnurl.SuccessAction{Message: "Payment Received!", Tag: "message"},
		Comment:            comment,
		Paid:               false,
		CreatedAt:          time.Now(),
		ParsedInvoice:      decoded_invoice,
		Nip57Receipt:       nip57Receipt,
		Nip57ReceiptRelays: nip57ReceiptRelays,
		AwaitInvoicePaid:   awaitPaid,
		Sender:             sender,
		Note:               note,
	}, nil

}
