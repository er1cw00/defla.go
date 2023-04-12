package app

import (
	"errors"
)

const MaxSession int = 5

var sessions map[string]*Session = make(map[string]*Session)

var ErrorSessionExist = errors.New("Session Exist")
var ErrorSessionNotExist = errors.New("Session Not Exist")
var ErrorSessionLimited = errors.New("Max Session Limited")

func CheckLimited() error {
	if len(sessions) >= MaxSession {
		return ErrorSessionLimited
	}
	return nil
}
func Get(id string) (*Session, error) {
	sess, found := sessions[id]
	if found {
		return sess, nil
	}
	return nil, ErrorSessionNotExist
}

func Append(id string, session *Session) error {

	_, found := sessions[id]
	if found {
		return ErrorSessionExist
	}
	sessions[id] = session
	return nil
}

func Remove(id string) {
	delete(sessions, id)
}
