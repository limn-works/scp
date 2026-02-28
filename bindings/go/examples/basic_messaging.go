// Basic messaging: create identity, create context, send and receive messages.
package main

import (
	"fmt"
	"log"

	scp "github.com/limn/scp-go"
)

func main() {
	if err := scp.Init(); err != nil {
		log.Fatal(err)
	}
	defer scp.Shutdown()

	// Create two identities
	alice, err := scp.NewIdentity("platform")
	if err != nil {
		log.Fatal(err)
	}
	bob, err := scp.NewIdentity("platform")
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("Alice DID:", alice.DID())
	fmt.Println("Bob DID:", bob.DID())

	// Alice creates a context
	ctxAlice, err := scp.NewContext(alice, scp.ContextParams{
		Ceiling:    []string{"msg:send", "msg:receive"},
		TTL:        3600,
		Governance: "single_admin",
	})
	if err != nil {
		log.Fatal(err)
	}
	defer ctxAlice.Close()
	fmt.Println("Context ID:", ctxAlice.ContextID())

	// Bob joins the context
	ctxBob, err := scp.JoinContext(bob, ctxAlice.ContextID())
	if err != nil {
		log.Fatal(err)
	}

	// Alice sends a message
	if err := ctxAlice.Send([]byte("Hello Bob, this is Alice")); err != nil {
		log.Fatal(err)
	}

	// Bob receives it
	msg := <-ctxBob.Receive()
	fmt.Printf("Bob received from %s: %s\n", msg.SenderDID, msg.Content)

	// Cleanup
	ctxBob.Leave()
}
