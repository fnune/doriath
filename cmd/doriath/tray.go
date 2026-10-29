package main

import (
	"context"
	"fmt"
	"image"
	"io"
	"time"

	"github.com/fnune/doriath/internal/tray"
	"github.com/fnune/doriath/internal/tray/sni"
	"github.com/fnune/doriath/internal/ui"
)

const trayPoll = 2 * time.Second

func showTray(ctx context.Context, counter tray.Counter, addr, token string, out io.Writer) {
	idle, err := trayImages(false)
	if err != nil {
		fmt.Fprintf(out, "The tray icon is off: %v\n", err)
		return
	}
	waiting, err := trayImages(true)
	if err != nil {
		fmt.Fprintf(out, "The tray icon is off: %v\n", err)
		return
	}
	item, err := sni.New(idle, waiting, func(activation string) {
		if err := openPage(context.Background(), addr, token, "", opener{activation: activation}, false, io.Discard); err != nil {
			fmt.Fprintf(out, "doriath: %v\n", err)
		}
	})
	if err != nil {
		fmt.Fprintf(out, "The tray icon is off: %v\n", err)
		return
	}
	ticker := time.NewTicker(trayPoll)
	go func() {
		defer ticker.Stop()
		defer func() { _ = item.Close() }()
		if err := tray.Run(ctx, counter, item, ticker.C); err != nil {
			fmt.Fprintf(out, "The tray icon is off: %v\n", err)
		}
	}()
}

func trayImages(waiting bool) ([]*image.NRGBA, error) {
	out := make([]*image.NRGBA, 0, len(tray.Sizes))
	for _, size := range tray.Sizes {
		img, err := tray.Render(ui.Icon(waiting), size)
		if err != nil {
			return nil, err
		}
		out = append(out, img)
	}
	return out, nil
}

func (l liveApprovals) Waiting(ctx context.Context) (int, error) {
	ctx, cancel := context.WithTimeout(ctx, trayPoll)
	defer cancel()
	sessions, err := l.Sessions(ctx)
	if err != nil {
		return 0, err
	}
	n := 0
	for _, s := range sessions {
		n += len(s.Requests)
	}
	return n, nil
}
