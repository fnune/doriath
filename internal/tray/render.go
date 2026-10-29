package tray

import (
	"encoding/xml"
	"errors"
	"fmt"
	"image"
	"image/color"
	"math"
	"strconv"
	"strings"
)

// Sizes are the square sizes in pixels that a status area picks from.
var Sizes = []int{16, 22, 24, 32, 48, 64}

// Render draws an SVG at size by size pixels. It knows only what the
// page's icons use, circles with a fill, a stroke and dashes, so that the
// tray draws the same files without an SVG library.
func Render(svg []byte, size int) (*image.NRGBA, error) {
	var doc struct {
		ViewBox string `xml:"viewBox,attr"`
		Shapes  []struct {
			XMLName xml.Name
			Attrs   []xml.Attr `xml:",any,attr"`
		} `xml:",any"`
	}
	if err := xml.Unmarshal(svg, &doc); err != nil {
		return nil, fmt.Errorf("read the icon: %w", err)
	}
	box, err := numbers(doc.ViewBox)
	if err != nil || len(box) != 4 || box[2] <= 0 || box[2] != box[3] {
		return nil, fmt.Errorf("the icon needs a square viewBox, not %q", doc.ViewBox)
	}
	var shapes []circle
	for _, s := range doc.Shapes {
		if s.XMLName.Local != "circle" {
			return nil, fmt.Errorf("the icon has a %s; only circles are drawn", s.XMLName.Local)
		}
		c, err := parseCircle(s.Attrs)
		if err != nil {
			return nil, err
		}
		c.cx, c.cy = c.cx-box[0], c.cy-box[1]
		shapes = append(shapes, c)
	}
	img := image.NewNRGBA(image.Rect(0, 0, size, size))
	scale := box[2] / float64(size)
	const samples = 4
	for py := range size {
		for px := range size {
			var r, g, b, a float64
			for sy := range samples {
				for sx := range samples {
					x := (float64(px) + (float64(sx)+0.5)/samples) * scale
					y := (float64(py) + (float64(sy)+0.5)/samples) * scale
					cr, cg, cb, ca := 0.0, 0.0, 0.0, 0.0
					for _, c := range shapes {
						for _, paint := range c.paints(x, y) {
							pa := float64(paint.A) / 255
							cr = float64(paint.R)/255*pa + cr*(1-pa)
							cg = float64(paint.G)/255*pa + cg*(1-pa)
							cb = float64(paint.B)/255*pa + cb*(1-pa)
							ca = pa + ca*(1-pa)
						}
					}
					r, g, b, a = r+cr, g+cg, b+cb, a+ca
				}
			}
			n := float64(samples * samples)
			if a == 0 {
				continue
			}
			img.SetNRGBA(px, py, color.NRGBA{R: unit(r / a), G: unit(g / a), B: unit(b / a), A: unit(a / n)})
		}
	}
	return img, nil
}

func unit(v float64) uint8 { return uint8(math.Round(math.Min(math.Max(v, 0), 1) * 255)) }

type circle struct {
	cx, cy, r   float64
	fill        *color.NRGBA
	stroke      *color.NRGBA
	strokeWidth float64
	dashes      []float64
}

func (c circle) paints(x, y float64) []color.NRGBA {
	var out []color.NRGBA
	dx, dy := x-c.cx, y-c.cy
	d := math.Hypot(dx, dy)
	if c.fill != nil && d <= c.r {
		out = append(out, *c.fill)
	}
	if c.stroke != nil && math.Abs(d-c.r) <= c.strokeWidth/2 && c.dashed(dx, dy) {
		out = append(out, *c.stroke)
	}
	return out
}

func (c circle) dashed(dx, dy float64) bool {
	if len(c.dashes) == 0 {
		return true
	}
	var period float64
	for _, d := range c.dashes {
		period += d
	}
	angle := math.Atan2(dy, dx)
	if angle < 0 {
		angle += 2 * math.Pi
	}
	at := math.Mod(angle*c.r, period)
	for i, d := range c.dashes {
		if at < d {
			return i%2 == 0
		}
		at -= d
	}
	return false
}

func parseCircle(attrs []xml.Attr) (circle, error) {
	c := circle{strokeWidth: 1}
	for _, a := range attrs {
		var err error
		switch a.Name.Local {
		case "cx":
			c.cx, err = strconv.ParseFloat(a.Value, 64)
		case "cy":
			c.cy, err = strconv.ParseFloat(a.Value, 64)
		case "r":
			c.r, err = strconv.ParseFloat(a.Value, 64)
		case "fill":
			c.fill, err = paint(a.Value)
		case "stroke":
			c.stroke, err = paint(a.Value)
		case "stroke-width":
			c.strokeWidth, err = strconv.ParseFloat(a.Value, 64)
		case "stroke-dasharray":
			c.dashes, err = numbers(a.Value)
			if len(c.dashes)%2 == 1 {
				c.dashes = append(c.dashes, c.dashes...)
			}
		default:
			err = errors.New("unknown attribute")
		}
		if err != nil {
			return circle{}, fmt.Errorf("circle %s=%q: %w", a.Name.Local, a.Value, err)
		}
	}
	return c, nil
}

func paint(v string) (*color.NRGBA, error) {
	if v == "none" {
		return nil, nil //nolint:nilnil // "none" is a valid paint that draws nothing
	}
	hex, ok := strings.CutPrefix(v, "#")
	if !ok || len(hex) != 6 {
		return nil, errors.New("want #rrggbb or none")
	}
	n, err := strconv.ParseUint(hex, 16, 32)
	if err != nil {
		return nil, err
	}
	return &color.NRGBA{R: uint8(n >> 16), G: uint8(n >> 8), B: uint8(n), A: 255}, nil
}

func numbers(s string) ([]float64, error) {
	var out []float64
	for f := range strings.FieldsFuncSeq(s, func(r rune) bool { return r == ' ' || r == ',' }) {
		n, err := strconv.ParseFloat(f, 64)
		if err != nil {
			return nil, err
		}
		out = append(out, n)
	}
	return out, nil
}
