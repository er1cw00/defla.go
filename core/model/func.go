package model

import (
	"encoding/json"
	"errors"
	"io/ioutil"
	"os"

	"github.com/er1cw00/btx.go/base/logger"
)

type FuncModel struct {
	Name  string `json: name`
	Start uint64 `json: start`
	End   uint64 `json: end`
}

func (m *FuncModel) UnmarshalJSON(b []byte) error {
	var err error = nil
	u := struct {
		Name  string `json: name`
		Start string `json: start`
		End   string `json: end`
	}{}
	if err = json.Unmarshal(b, &u); err != nil {
		logger.Errorf("Marshal fail, error: %v", err)
		return err
	}
	m.Name = u.Name

	if m.Start, err = HexStringToUint64(u.Start); err != nil {
		logger.Errorf("Marshal fail for 'start', error: %v", err)
		return err
	}
	if m.End, err = HexStringToUint64(u.End); err != nil {
		logger.Errorf("Marshal fail for 'end', error: %v", err)
		return err
	}
	return nil
}

func UnmarshalFuncModel(path string) ([]FuncModel, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	var list []FuncModel
	context, err := ioutil.ReadAll(f)
	if err != nil {
		return nil, err
	}
	err = json.Unmarshal(context, &list)
	if err != nil {
		return nil, err
	}
	if len(list) == 0 {
		return nil, errors.New("not func need to be defla")
	}
	return list, nil
}
