package certificate_searcher

import (
	"errors"
	"math"
	"unicode"
)

var qwertyAdjacencyMatrix map[rune]map[rune]bool
var qwertyAdjacentRunes map[rune][]rune
var asciiLowerAlphanumeric string

type coordinate struct {
	x float64
	y float64
}

func (c1 coordinate) distance(c2 coordinate) float64 {
	return math.Sqrt(math.Pow(c1.x-c2.x, 2) + math.Pow(c1.y-c2.y, 2))
}

func init() {
	qwertyAdjacencyMatrix = make(map[rune]map[rune]bool)
	qwertyAdjacentRunes = make(map[rune][]rune)
	asciiLowerAlphanumeric = "abcdefghijklmnopqrstuvwxyz1234567890-"

	qwertyCoordinates := make(map[rune]coordinate)
	qwertyCoordinates['1'] = coordinate{x: 0, y: 3}
	qwertyCoordinates['2'] = coordinate{x: 1, y: 3}
	qwertyCoordinates['3'] = coordinate{x: 2, y: 3}
	qwertyCoordinates['4'] = coordinate{x: 3, y: 3}
	qwertyCoordinates['5'] = coordinate{x: 4, y: 3}
	qwertyCoordinates['6'] = coordinate{x: 5, y: 3}
	qwertyCoordinates['7'] = coordinate{x: 6, y: 3}
	qwertyCoordinates['8'] = coordinate{x: 7, y: 3}
	qwertyCoordinates['9'] = coordinate{x: 8, y: 3}
	qwertyCoordinates['0'] = coordinate{x: 9, y: 3}
	qwertyCoordinates['-'] = coordinate{x: 10, y: 3}

	qwertyCoordinates['q'] = coordinate{x: 0.5, y: 2}
	qwertyCoordinates['w'] = coordinate{x: 1.5, y: 2}
	qwertyCoordinates['e'] = coordinate{x: 2.5, y: 2}
	qwertyCoordinates['r'] = coordinate{x: 3.5, y: 2}
	qwertyCoordinates['t'] = coordinate{x: 4.5, y: 2}
	qwertyCoordinates['y'] = coordinate{x: 5.5, y: 2}
	qwertyCoordinates['u'] = coordinate{x: 6.5, y: 2}
	qwertyCoordinates['i'] = coordinate{x: 7.5, y: 2}
	qwertyCoordinates['o'] = coordinate{x: 8.5, y: 2}
	qwertyCoordinates['p'] = coordinate{x: 9.5, y: 2}

	qwertyCoordinates['a'] = coordinate{x: 1, y: 1}
	qwertyCoordinates['s'] = coordinate{x: 2, y: 1}
	qwertyCoordinates['d'] = coordinate{x: 3, y: 1}
	qwertyCoordinates['f'] = coordinate{x: 4, y: 1}
	qwertyCoordinates['g'] = coordinate{x: 5, y: 1}
	qwertyCoordinates['h'] = coordinate{x: 6, y: 1}
	qwertyCoordinates['j'] = coordinate{x: 7, y: 1}
	qwertyCoordinates['k'] = coordinate{x: 8, y: 1}
	qwertyCoordinates['l'] = coordinate{x: 9, y: 1}

	qwertyCoordinates['z'] = coordinate{x: 1.5, y: 0}
	qwertyCoordinates['x'] = coordinate{x: 2.5, y: 0}
	qwertyCoordinates['c'] = coordinate{x: 3.5, y: 0}
	qwertyCoordinates['v'] = coordinate{x: 4.5, y: 0}
	qwertyCoordinates['b'] = coordinate{x: 5.5, y: 0}
	qwertyCoordinates['n'] = coordinate{x: 6.5, y: 0}
	qwertyCoordinates['m'] = coordinate{x: 7.5, y: 0}

	for _, r1 := range asciiLowerAlphanumeric {
		if len(qwertyAdjacencyMatrix[r1]) == 0 {
			qwertyAdjacencyMatrix[r1] = make(map[rune]bool)
		}
		if len(qwertyAdjacentRunes[r1]) == 0 {
			qwertyAdjacentRunes[r1] = make([]rune, 0)
		}

		for _, r2 := range asciiLowerAlphanumeric {
			dist := qwertyCoordinates[r1].distance(qwertyCoordinates[r2])

			if dist > 0 && dist < 1.5 {
				qwertyAdjacencyMatrix[r1][r2] = true
			}
			// move the statement here so that all the combinations are possible
			qwertyAdjacentRunes[r1] = append(qwertyAdjacentRunes[r1], r2)
		}
	}
}

func QwertyAdjacent(char1 rune, char2 rune) (bool, error) {
	char1 = unicode.ToLower(char1)
	char2 = unicode.ToLower(char2)

	if !QwertyAlphanumeric(char1) {
		return false, errors.New("Unrecognized QWERTY keyboard character: " + string(char1))
	}
	if !QwertyAlphanumeric(char2) {
		return false, errors.New("Unrecognized QWERTY keyboard character: " + string(char2))
	}

	return qwertyAdjacencyMatrix[char1][char2], nil
}

func QwertyAdjacentRunes(char rune) ([]rune, error) {
	char = unicode.ToLower(char)
	if !QwertyAlphanumeric(char) {
		return nil, errors.New("Unrecognized QWERTY keyboard character: " + string(char))
	}
	
	return qwertyAdjacentRunes[char], nil
}

func QwertyAlphanumeric(char rune) bool {
	char = unicode.ToLower(char)
	for _, alphaNum := range asciiLowerAlphanumeric {
		if char == alphaNum {
			return true
		}
	}

	return false
}
