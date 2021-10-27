package mockoidc

import "sync"

type SpecialUserQueue struct {
	sync.Mutex
	Queue map[string][]User
}

// UserQueue manages the queue of Users returned for each
// call to the authorize endpoint
type UserQueue struct {
	sync.Mutex
	Queue []User
}

// CodeQueue manages the queue of codes returned for each
// call to the authorize endpoint
type CodeQueue struct {
	sync.Mutex
	Queue []string
}

// ErrorQueue manages the queue of errors for handlers to return
type ErrorQueue struct {
	sync.Mutex
	Queue []*ServerError
}

// ServerError is a tester-defined error for a handler to return
type ServerError struct {
	Code        int
	Error       string
	Description string
}

func (q *SpecialUserQueue) Push(idp string, user User) {
	q.Lock()
	defer q.Unlock()
	q.Queue[idp] = append(q.Queue[idp], user)
}

func (q *SpecialUserQueue) Pop(idp string) User {
	q.Lock()
	defer q.Unlock()
	if _, ok := q.Queue[idp]; ok {
		if len(q.Queue[idp]) == 0 {
			return DefaultUser()
		}

		var user User
		user, q.Queue[idp] = q.Queue[idp][0], q.Queue[idp][1:]
		return user
	} else {
		return DefaultUser()
	}
}

func (q *SpecialUserQueue) GetIdpsExhaustedWithUsers() []string {
	returnString := []string{}
	q.Lock()
	defer q.Unlock()
	for idp := range q.Queue {
		if len(q.Queue[idp]) == 0 {
			returnString = append(returnString, idp)
		}
	}

	return returnString
}

// Push adds a User to the Queue to be set in subsequent calls to the
// `authorization_endpoint`
func (q *UserQueue) Push(user User) {
	q.Lock()
	defer q.Unlock()
	q.Queue = append(q.Queue, user)
}

// Pop a User from the Queue. If empty, return `DefaultUser()`
func (q *UserQueue) Pop() User {
	q.Lock()
	defer q.Unlock()

	if len(q.Queue) == 0 {
		return DefaultUser()
	}

	var user User
	user, q.Queue = q.Queue[0], q.Queue[1:]
	return user
}

// Push adds a code to the Queue to be returned by subsequent
// `authorization_endpoint` calls as the code
func (q *CodeQueue) Push(code string) {
	q.Lock()
	defer q.Unlock()
	q.Queue = append(q.Queue, code)
}

// Pop a `code` from the Queue. If empty, return a random code
func (q *CodeQueue) Pop() (string, error) {
	q.Lock()
	defer q.Unlock()

	if len(q.Queue) == 0 {
		code, err := randomNonce(24)
		if err != nil {
			return "", err
		}
		return code, nil
	}

	var code string
	code, q.Queue = q.Queue[0], q.Queue[1:]
	return code, nil
}

// Push adds a ServerError to the Queue to be returned in subsequent
// handler calls
func (q *ErrorQueue) Push(se *ServerError) {
	q.Lock()
	defer q.Unlock()
	q.Queue = append(q.Queue, se)
}

// Pop a ServerError from the Queue. If empty, return nil
func (q *ErrorQueue) Pop() *ServerError {
	q.Lock()
	defer q.Unlock()

	if len(q.Queue) == 0 {
		return nil
	}

	var se *ServerError
	se, q.Queue = q.Queue[0], q.Queue[1:]
	return se
}
