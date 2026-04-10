//! Deck management for mental poker.
//!
//! This module provides utilities for creating, encoding, and managing
//! decks of playing cards for use in mental poker games.

use crate::error::{MentalPokerError, Result};
use crate::protocol::MentalPokerProtocol;
use crate::types::*;
use std::collections::HashMap;

/// Standard playing card suits.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Suit {
    Clubs,
    Diamonds,
    Hearts,
    Spades,
}

impl Suit {
    /// All suits in order.
    pub const ALL: [Suit; 4] = [Suit::Clubs, Suit::Diamonds, Suit::Hearts, Suit::Spades];

    /// Get the suit symbol.
    pub fn symbol(&self) -> &'static str {
        match self {
            Suit::Clubs => "♣",
            Suit::Diamonds => "♦",
            Suit::Hearts => "♥",
            Suit::Spades => "♠",
        }
    }
}

/// Standard playing card ranks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Rank {
    Two = 2,
    Three = 3,
    Four = 4,
    Five = 5,
    Six = 6,
    Seven = 7,
    Eight = 8,
    Nine = 9,
    Ten = 10,
    Jack = 11,
    Queen = 12,
    King = 13,
    Ace = 14,
}

impl Rank {
    /// All ranks in order.
    pub const ALL: [Rank; 13] = [
        Rank::Two,
        Rank::Three,
        Rank::Four,
        Rank::Five,
        Rank::Six,
        Rank::Seven,
        Rank::Eight,
        Rank::Nine,
        Rank::Ten,
        Rank::Jack,
        Rank::Queen,
        Rank::King,
        Rank::Ace,
    ];

    /// Get the rank symbol.
    pub fn symbol(&self) -> &'static str {
        match self {
            Rank::Two => "2",
            Rank::Three => "3",
            Rank::Four => "4",
            Rank::Five => "5",
            Rank::Six => "6",
            Rank::Seven => "7",
            Rank::Eight => "8",
            Rank::Nine => "9",
            Rank::Ten => "10",
            Rank::Jack => "J",
            Rank::Queen => "Q",
            Rank::King => "K",
            Rank::Ace => "A",
        }
    }
}

/// A classic playing card with suit and rank.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct PlayingCard {
    pub rank: Rank,
    pub suit: Suit,
}

impl PlayingCard {
    /// Create a new playing card.
    pub fn new(rank: Rank, suit: Suit) -> Self {
        Self { rank, suit }
    }

    /// Get the card's display string.
    pub fn display(&self) -> String {
        format!("{}{}", self.rank.symbol(), self.suit.symbol())
    }
}

impl std::fmt::Display for PlayingCard {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.display())
    }
}

/// A mapping between cryptographic cards and playing cards.
#[derive(Debug, Clone)]
pub struct CardEncoding {
    /// Map from crypto card to playing card
    card_to_playing: HashMap<[u8; 64], PlayingCard>,
    /// Map from playing card to crypto card
    playing_to_card: HashMap<PlayingCard, Card>,
}

impl CardEncoding {
    /// Create a new random encoding for a standard 52-card deck.
    pub fn standard_deck() -> Self {
        let mut card_to_playing = HashMap::new();
        let mut playing_to_card = HashMap::new();

        let mut index = 1u64; // Start from 1 to avoid identity point issues
        for &rank in &Rank::ALL {
            for &suit in &Suit::ALL {
                let playing = PlayingCard::new(rank, suit);
                let card = Card::from_index(index);

                // Use the card point's serialized form as key
                if let Ok(affine) = krusty_kms_crypto::StarkCurve::projective_to_affine(&card.point)
                {
                    let mut key = [0u8; 64];
                    key[..32].copy_from_slice(&affine.x().to_bytes_be());
                    key[32..].copy_from_slice(&affine.y().to_bytes_be());
                    card_to_playing.insert(key, playing);
                    playing_to_card.insert(playing, card);
                }

                index += 1;
            }
        }

        Self {
            card_to_playing,
            playing_to_card,
        }
    }

    /// Look up the playing card for a cryptographic card.
    pub fn decode(&self, card: &Card) -> Result<PlayingCard> {
        let affine = krusty_kms_crypto::StarkCurve::projective_to_affine(&card.point)?;
        let mut key = [0u8; 64];
        key[..32].copy_from_slice(&affine.x().to_bytes_be());
        key[32..].copy_from_slice(&affine.y().to_bytes_be());

        self.card_to_playing
            .get(&key)
            .cloned()
            .ok_or(MentalPokerError::InvalidCard)
    }

    /// Look up the cryptographic card for a playing card.
    pub fn encode(&self, playing: &PlayingCard) -> Result<Card> {
        self.playing_to_card
            .get(playing)
            .cloned()
            .ok_or(MentalPokerError::InvalidCard)
    }

    /// Get all cryptographic cards.
    pub fn all_cards(&self) -> Vec<Card> {
        self.playing_to_card.values().cloned().collect()
    }
}

/// A deck of masked cards.
#[derive(Debug, Clone)]
pub struct MaskedDeck {
    /// The masked cards in the deck
    pub cards: Vec<MaskedCard>,
    /// The proofs for each masking operation
    pub proofs: Vec<DLEqualityProof>,
}

impl MaskedDeck {
    /// Create a new masked deck from open cards.
    pub fn new(open_cards: &[Card], aggregate_pk: &PublicKey) -> Result<Self> {
        let mut cards = Vec::with_capacity(open_cards.len());
        let mut proofs = Vec::with_capacity(open_cards.len());

        for card in open_cards {
            let (masked, proof) = MentalPokerProtocol::mask(card, aggregate_pk, None)?;
            cards.push(masked);
            proofs.push(proof);
        }

        Ok(Self { cards, proofs })
    }

    /// Create a standard 52-card masked deck.
    pub fn standard(encoding: &CardEncoding, aggregate_pk: &PublicKey) -> Result<Self> {
        Self::new(&encoding.all_cards(), aggregate_pk)
    }

    /// Shuffle and remask the deck.
    pub fn shuffle(&self, aggregate_pk: &PublicKey) -> Result<Self> {
        let n = self.cards.len();
        let permutation = Permutation::random(n);
        let factors: Vec<_> = (0..n)
            .map(|_| krusty_kms_crypto::scalar::random_felt())
            .collect();

        let shuffled = MentalPokerProtocol::shuffle_and_remask(
            &self.cards,
            aggregate_pk,
            &permutation,
            &factors,
        )?;

        let (cards, proofs): (Vec<_>, Vec<_>) = shuffled.into_iter().unzip();
        Ok(Self { cards, proofs })
    }

    /// Get the number of cards in the deck.
    pub fn len(&self) -> usize {
        self.cards.len()
    }

    /// Check if the deck is empty.
    pub fn is_empty(&self) -> bool {
        self.cards.is_empty()
    }

    /// Draw a card from the top of the deck.
    pub fn draw(&mut self) -> Option<MaskedCard> {
        if self.cards.is_empty() {
            None
        } else {
            self.proofs.remove(0);
            Some(self.cards.remove(0))
        }
    }

    /// Draw multiple cards from the top of the deck.
    pub fn draw_n(&mut self, n: usize) -> Vec<MaskedCard> {
        let actual = n.min(self.cards.len());
        self.proofs.drain(0..actual);
        self.cards.drain(0..actual).collect()
    }
}

/// A player's hand of cards.
#[derive(Debug, Clone)]
pub struct Hand {
    /// The masked cards in hand
    pub masked_cards: Vec<MaskedCard>,
    /// The revealed playing cards (if any)
    pub revealed: Vec<Option<PlayingCard>>,
}

impl Hand {
    /// Create a new empty hand.
    pub fn new() -> Self {
        Self {
            masked_cards: Vec::new(),
            revealed: Vec::new(),
        }
    }

    /// Add a card to the hand.
    pub fn add(&mut self, card: MaskedCard) {
        self.masked_cards.push(card);
        self.revealed.push(None);
    }

    /// Reveal a card using reveal tokens.
    pub fn reveal(
        &mut self,
        index: usize,
        reveal_tokens: &[(RevealToken, DLEqualityProof, PublicKey)],
        encoding: &CardEncoding,
    ) -> Result<PlayingCard> {
        if index >= self.masked_cards.len() {
            return Err(MentalPokerError::CardNotFound);
        }

        let masked = &self.masked_cards[index];
        let open_card = MentalPokerProtocol::unmask(masked, reveal_tokens)?;
        let playing = encoding.decode(&open_card)?;

        self.revealed[index] = Some(playing);
        Ok(playing)
    }

    /// Get the number of cards in hand.
    pub fn len(&self) -> usize {
        self.masked_cards.len()
    }

    /// Check if hand is empty.
    pub fn is_empty(&self) -> bool {
        self.masked_cards.is_empty()
    }
}

impl Default for Hand {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_card_encoding() {
        let encoding = CardEncoding::standard_deck();
        assert_eq!(encoding.all_cards().len(), 52);
    }

    #[test]
    fn test_encode_decode() {
        let encoding = CardEncoding::standard_deck();
        let ace_spades = PlayingCard::new(Rank::Ace, Suit::Spades);

        let card = encoding.encode(&ace_spades).unwrap();
        let decoded = encoding.decode(&card).unwrap();
        assert_eq!(decoded, ace_spades);
    }

    #[test]
    fn test_masked_deck() {
        let encoding = CardEncoding::standard_deck();
        let (pk, _sk) = MentalPokerProtocol::player_keygen();

        let deck = MaskedDeck::standard(&encoding, &pk).unwrap();
        assert_eq!(deck.len(), 52);
    }

    #[test]
    fn test_deck_shuffle() {
        let encoding = CardEncoding::standard_deck();
        let (pk, _sk) = MentalPokerProtocol::player_keygen();

        let deck = MaskedDeck::standard(&encoding, &pk).unwrap();
        let shuffled = deck.shuffle(&pk).unwrap();
        assert_eq!(shuffled.len(), 52);
    }

    #[test]
    fn test_hand() {
        let encoding = CardEncoding::standard_deck();
        let (pk1, sk1) = MentalPokerProtocol::player_keygen();
        let (pk2, sk2) = MentalPokerProtocol::player_keygen();
        let aggregate_pk = pk1.add(&pk2);

        let ace_spades = PlayingCard::new(Rank::Ace, Suit::Spades);
        let card = encoding.encode(&ace_spades).unwrap();

        let (masked, _) = MentalPokerProtocol::mask(&card, &aggregate_pk, None).unwrap();

        // Compute reveal tokens before adding to hand
        let (token1, proof1) =
            MentalPokerProtocol::compute_reveal_token(&masked, &sk1, &pk1).unwrap();
        let (token2, proof2) =
            MentalPokerProtocol::compute_reveal_token(&masked, &sk2, &pk2).unwrap();

        let mut hand = Hand::new();
        hand.add(masked);
        assert_eq!(hand.len(), 1);

        let tokens = vec![(token1, proof1, pk1), (token2, proof2, pk2)];
        let revealed = hand.reveal(0, &tokens, &encoding).unwrap();
        assert_eq!(revealed, ace_spades);
    }

    #[test]
    fn test_playing_card_display() {
        let card = PlayingCard::new(Rank::Ace, Suit::Spades);
        assert_eq!(card.display(), "A♠");
    }
}
