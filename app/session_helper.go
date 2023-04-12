package app

import (
	"errors"
)

var sessions map[string]*Session = make(map[string]*Session)

var ErrorSessionExist = errors.New("Session Exist")
var ErrorSessionNotExist = errors.New("Session Not Exist")

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
