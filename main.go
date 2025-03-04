package main

import (
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

// Game represents a Tic-Tac-Toe game
type Game struct {
	Board     [3][3]string `json:"board"`
	NextTurn  string       `json:"nextTurn"`
	GameID    string       `json:"gameId"`
	Winner    string       `json:"winner"`
	GameOver  bool         `json:"gameOver"`
	PlayerX   *Player
	PlayerO   *Player
	mutex     sync.Mutex
}

// Player represents a connected client
type Player struct {
	Conn      *websocket.Conn
	LastPing  time.Time
	IsWaiting bool
}

// Message represents a message sent between client and server
type Message struct {
	Type      string `json:"type"`
	GameID    string `json:"gameId,omitempty"`
	Row       int    `json:"row,omitempty"`
	Col       int    `json:"col,omitempty"`
	Player    string `json:"player,omitempty"`
	GameState *Game  `json:"gameState,omitempty"`
}

var (
	// Upgrader for WebSocket connections
	upgrader = websocket.Upgrader{
		ReadBufferSize:  1024,
		WriteBufferSize: 1024,
		CheckOrigin: func(r *http.Request) bool {
			return true // Allow all connections for simplicity
		},
	}

	// Games map to store active games
	games = make(map[string]*Game)
	// Mutex to protect games map
	gamesMutex sync.Mutex

	// Players list
	players = make(map[*websocket.Conn]*Player)
	playersMutex sync.Mutex
)

func main() {
	// Serve static files
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
        http.ServeFile(w, r, "index.html")
    })
	log.Println("Static file server configured for ./static directory")

	// WebSocket endpoint
	http.HandleFunc("/ws", handleWebSocket)
	log.Println("WebSocket endpoint registered at /ws")

	// Start the server
	log.Println("Server starting on http://localhost:8080")
	log.Println("To play: Open http://localhost:8080 in two different browser tabs")
	log.Fatal(http.ListenAndServe(":8080", nil))
}

func handleWebSocket(w http.ResponseWriter, r *http.Request) {
	// Upgrade HTTP connection to WebSocket
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Println("Error upgrading to WebSocket:", err)
		return
	}

	// Set connection parameters for better stability
	conn.SetReadLimit(1024 * 1024) // 1MB
	conn.SetReadDeadline(time.Now().Add(60 * time.Second))
	conn.SetPongHandler(func(string) error {
		conn.SetReadDeadline(time.Now().Add(60 * time.Second))
		return nil
	})

	log.Println("New client connected")

	// Create a new player
	player := &Player{
		Conn:      conn,
		LastPing:  time.Now(),
		IsWaiting: false,
	}

	// Add to players map
	playersMutex.Lock()
	players[conn] = player
	playersMutex.Unlock()

	// Setup ping/pong
	go keepAlive(conn)

	// Find a game for this player
	go findGame(player)

	// Handle incoming messages
	for {
		var msg Message
		err := conn.ReadJSON(&msg)
		if err != nil {
			log.Println("Error reading message:", err)
			handlePlayerDisconnect(conn)
			break
		}

		handleMessage(conn, msg)
	}
}

func keepAlive(conn *websocket.Conn) {
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()
	
	for range ticker.C {
		playersMutex.Lock()
		player, exists := players[conn]
		playersMutex.Unlock()
		
		if !exists {
			return
		}
		
		if err := conn.WriteMessage(websocket.PingMessage, nil); err != nil {
			handlePlayerDisconnect(conn)
			return
		}
		
		if time.Since(player.LastPing) > 60*time.Second {
			log.Println("Player timed out")
			handlePlayerDisconnect(conn)
			return
		}
	}
}

func findGame(player *Player) {
	// First, we need to mark this player as waiting
	playersMutex.Lock()
	player.IsWaiting = true
	playersMutex.Unlock()

	// Inform the player they're waiting
	msg := Message{
		Type: "waiting",
	}
	if err := player.Conn.WriteJSON(msg); err != nil {
		log.Println("Error sending waiting message:", err)
		handlePlayerDisconnect(player.Conn)
		return
	}

	// Keep checking for another waiting player
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		playersMutex.Lock()
		
		// Check if this player is still connected and waiting
		if _, exists := players[player.Conn]; !exists || !player.IsWaiting {
			playersMutex.Unlock()
			return
		}

		// Look for another waiting player
		var opponent *Player
		for _, p := range players {
			if p != player && p.IsWaiting {
				opponent = p
				break
			}
		}

		if opponent != nil {
			// Found an opponent, mark both as not waiting
			player.IsWaiting = false
			opponent.IsWaiting = false
			playersMutex.Unlock()
			
			// Create a game with these two players
			createGame(player, opponent)
			return
		}
		
		playersMutex.Unlock()
	}
}

func createGame(playerX, playerO *Player) {
	// Generate a game ID
	gameID := generateGameID()
	
	// Create the game
	game := &Game{
		Board:    [3][3]string{{}, {}, {}},
		NextTurn: "X",
		GameID:   gameID,
		PlayerX:  playerX,
		PlayerO:  playerO,
	}
	
	// Add to games map
	gamesMutex.Lock()
	games[gameID] = game
	gamesMutex.Unlock()
	
	// Tell player X
	msgX := Message{
		Type:      "game_start",
		GameID:    gameID,
		Player:    "X",
		GameState: game,
	}
	if err := playerX.Conn.WriteJSON(msgX); err != nil {
		log.Println("Error sending game start to player X:", err)
		handlePlayerDisconnect(playerX.Conn)
		handlePlayerDisconnect(playerO.Conn)
		return
	}
	
	// Tell player O
	msgO := Message{
		Type:      "game_start",
		GameID:    gameID,
		Player:    "O",
		GameState: game,
	}
	if err := playerO.Conn.WriteJSON(msgO); err != nil {
		log.Println("Error sending game start to player O:", err)
		handlePlayerDisconnect(playerO.Conn)
		return
	}
	
	log.Println("Game created successfully:", gameID)
}

func handleMessage(conn *websocket.Conn, msg Message) {
	switch msg.Type {
	case "move":
		handleMove(conn, msg)
	case "restart":
		handleRestart(conn, msg)
	case "pong":
		// Update last ping time
		playersMutex.Lock()
		if player, exists := players[conn]; exists {
			player.LastPing = time.Now()
		}
		playersMutex.Unlock()
	}
}

func handleMove(conn *websocket.Conn, msg Message) {
	gamesMutex.Lock()
	game, exists := games[msg.GameID]
	gamesMutex.Unlock()

	if !exists {
		log.Println("Game not found:", msg.GameID)
		return
	}

	game.mutex.Lock()
	defer game.mutex.Unlock()

	// Check if game is over
	if game.GameOver {
		return
	}

	// Check if it's the player's turn
	playerMark := getPlayerMark(conn, game)
	if playerMark != game.NextTurn {
		return
	}

	// Check if the cell is empty
	if game.Board[msg.Row][msg.Col] != "" {
		return
	}

	// Make the move
	game.Board[msg.Row][msg.Col] = playerMark

	// Check for a winner
	if winner := checkWinner(game.Board); winner != "" {
		game.Winner = winner
		game.GameOver = true
	} else if isBoardFull(game.Board) {
		game.GameOver = true
	}

	// Switch turn
	if game.NextTurn == "X" {
		game.NextTurn = "O"
	} else {
		game.NextTurn = "X"
	}

	// Broadcast updated game state to both players
	broadcastGameState(game)
}

func handleRestart(conn *websocket.Conn, msg Message) {
	gamesMutex.Lock()
	game, exists := games[msg.GameID]
	gamesMutex.Unlock()

	if !exists {
		log.Println("Game not found:", msg.GameID)
		return
	}

	game.mutex.Lock()
	defer game.mutex.Unlock()

	// Reset the game
	game.Board = [3][3]string{{}, {}, {}}
	game.NextTurn = "X"
	game.Winner = ""
	game.GameOver = false

	// Broadcast updated game state
	broadcastGameState(game)
}

func handlePlayerDisconnect(conn *websocket.Conn) {
	playersMutex.Lock()
	_, exists := players[conn]
	if exists {
		delete(players, conn)
	}
	playersMutex.Unlock()
	
	if !exists {
		return
	}

	// Find any game this player is in
	gamesMutex.Lock()
	
	for id, game := range games {
		if (game.PlayerX != nil && game.PlayerX.Conn == conn) || 
		   (game.PlayerO != nil && game.PlayerO.Conn == conn) {
			
			// Notify the other player
			var otherPlayer *Player
			if game.PlayerX != nil && game.PlayerX.Conn == conn {
				otherPlayer = game.PlayerO
			} else {
				otherPlayer = game.PlayerX
			}

			if otherPlayer != nil {
				msg := Message{
					Type: "opponent_disconnected",
				}
				otherPlayer.Conn.WriteJSON(msg)
				
				// Mark the other player as waiting for a new game
				playersMutex.Lock()
				otherPlayer.IsWaiting = true
				playersMutex.Unlock()
				
				// Start finding a new game for the remaining player
				go findGame(otherPlayer)
			}
			
			// Remove the game
			delete(games, id)
			break
		}
	}
	
	gamesMutex.Unlock()
	
	// Close the connection
	conn.Close()
}

func broadcastGameState(game *Game) {
	// Create state message
	msg := Message{
		Type:      "update",
		GameState: game,
	}

	// Send to both players
	if game.PlayerX != nil {
		game.PlayerX.Conn.WriteJSON(msg)
	}
	if game.PlayerO != nil {
		game.PlayerO.Conn.WriteJSON(msg)
	}
}

func checkWinner(board [3][3]string) string {
	// Check rows
	for i := 0; i < 3; i++ {
		if board[i][0] != "" && board[i][0] == board[i][1] && board[i][1] == board[i][2] {
			return board[i][0]
		}
	}

	// Check columns
	for i := 0; i < 3; i++ {
		if board[0][i] != "" && board[0][i] == board[1][i] && board[1][i] == board[2][i] {
			return board[0][i]
		}
	}

	// Check diagonals
	if board[0][0] != "" && board[0][0] == board[1][1] && board[1][1] == board[2][2] {
		return board[0][0]
	}
	if board[0][2] != "" && board[0][2] == board[1][1] && board[1][1] == board[2][0] {
		return board[0][2]
	}

	return ""
}

func isBoardFull(board [3][3]string) bool {
	for i := 0; i < 3; i++ {
		for j := 0; j < 3; j++ {
			if board[i][j] == "" {
				return false
			}
		}
	}
	return true
}

func getPlayerMark(conn *websocket.Conn, game *Game) string {
	if game.PlayerX != nil && game.PlayerX.Conn == conn {
		return "X"
	}
	if game.PlayerO != nil && game.PlayerO.Conn == conn {
		return "O"
	}
	return ""
}

func generateGameID() string {
	// Simple approach for demo purposes
	// In production, use a proper UUID generator
	return "game-" + randString(8)
}

func randString(n int) string {
	const letters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, n)
	for i := range b {
		b[i] = letters[i%len(letters)]
	}
	return string(b)
}