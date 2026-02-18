package ffi

import "testing"

func TestCoinTypes(t *testing.T) {
	tongo, starknet, tongoView, nostr := CoinTypes()

	if tongo != 5454 {
		t.Fatalf("unexpected tongo coin type: %d", tongo)
	}
	if starknet != 9004 {
		t.Fatalf("unexpected starknet coin type: %d", starknet)
	}
	if tongoView != 5353 {
		t.Fatalf("unexpected tongo view coin type: %d", tongoView)
	}
	if nostr != 1237 {
		t.Fatalf("unexpected nostr coin type: %d", nostr)
	}
}

func TestFeltHexRoundTrip(t *testing.T) {
	felt, err := FeltFromHex("0x2a")
	if err != nil {
		t.Fatalf("felt from hex failed: %v", err)
	}

	hex, err := FeltToHex(felt)
	if err != nil {
		t.Fatalf("felt to hex failed: %v", err)
	}

	want := "0x000000000000000000000000000000000000000000000000000000000000002a"
	if hex != want {
		t.Fatalf("unexpected roundtrip hex: %s", hex)
	}
}
