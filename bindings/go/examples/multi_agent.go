// Multi-agent coordination: multiple agents collaborating in a shared context.
package main

import (
	"fmt"
	"log"
	"sync"

	scp "github.com/limn/scp-go"
)

func runAgent(name string, identity *scp.Identity, contextID string, wg *sync.WaitGroup) {
	defer wg.Done()

	ctx, err := scp.JoinContext(identity, contextID)
	if err != nil {
		log.Printf("[%s] Failed to join: %v", name, err)
		return
	}
	fmt.Printf("[%s] Joined context %s\n", name, contextID)

	if err := ctx.Send([]byte(fmt.Sprintf("[%s] reporting in", name))); err != nil {
		log.Printf("[%s] Send failed: %v", name, err)
		return
	}

	count := 0
	for msg := range ctx.Receive() {
		sender := msg.SenderDID
		if len(sender) > 16 {
			sender = sender[:16]
		}
		fmt.Printf("[%s] Received from %s...: %s\n", name, sender, msg.Content)
		count++
		if count >= 2 {
			break
		}
	}

	ctx.Leave()
	fmt.Printf("[%s] Left context\n", name)
}

func main() {
	if err := scp.Init(); err != nil {
		log.Fatal(err)
	}
	defer scp.Shutdown()

	// Create identities for coordinator and two agents
	coordinator, err := scp.NewIdentity("platform")
	if err != nil {
		log.Fatal(err)
	}
	agentA, err := scp.NewIdentity("platform")
	if err != nil {
		log.Fatal(err)
	}
	agentB, err := scp.NewIdentity("platform")
	if err != nil {
		log.Fatal(err)
	}

	// Coordinator creates the context
	ctx, err := scp.NewContext(coordinator, scp.ContextParams{
		Ceiling:    []string{"msg:send", "msg:receive", "tool:invoke"},
		Governance: "single_admin",
		Roles: map[string][]string{
			"agent": {"msg:send", "msg:receive", "tool:invoke"},
		},
	})
	if err != nil {
		log.Fatal(err)
	}
	defer ctx.Close()
	fmt.Println("Context created:", ctx.ContextID())

	// Mint UCANs for each agent
	_, err = scp.MintUcan(coordinator, agentA.DID(), []string{"msg:send", "msg:receive"}, ctx.ContextID())
	if err != nil {
		log.Fatal(err)
	}
	_, err = scp.MintUcan(coordinator, agentB.DID(), []string{"msg:send", "msg:receive"}, ctx.ContextID())
	if err != nil {
		log.Fatal(err)
	}

	// Run agents concurrently
	var wg sync.WaitGroup
	wg.Add(2)
	go runAgent("Agent-A", agentA, ctx.ContextID(), &wg)
	go runAgent("Agent-B", agentB, ctx.ContextID(), &wg)
	wg.Wait()
}
