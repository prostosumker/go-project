package main

import (
	"embed"
	"fmt"
	"net/http"
)

//go:embed static/*
var content embed.FS

func main() {
	fs := http.FileServer(http.FS(content))
	http.Handle("/", fs)

	fmt.Println("Server is running on http://localhost:8080")
	err := http.ListenAndServe(":8080", nil)
	if err != nil {
		panic(err)
	}
}
