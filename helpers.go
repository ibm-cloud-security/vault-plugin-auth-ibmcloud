package iam_plugin

import (
	"fmt"
	"io/ioutil"
	"net/http"
)

func getURL(endpoint, path string, pathReplacements ...string) string {
	pathSubs := make([]interface{}, len(pathReplacements))
	for i, v := range pathReplacements {
		pathSubs[i] = v
	}
	return fmt.Sprintf("%s%s", endpoint, fmt.Sprintf(path, pathSubs...))
}

func httpRequest(client *http.Client, r *http.Request) ([]byte, int, error) {
	resp, err := client.Do(r)
	if err != nil {
		return nil, resp.StatusCode, err
	}
	defer closeResponse(resp)

	var body []byte
	if resp.Body != nil {
		body, err = ioutil.ReadAll(resp.Body)
		if err != nil {
			return nil, resp.StatusCode, err
		}
	}

	return body, resp.StatusCode, nil
}

func httpRequestCheckStatus(client *http.Client, r *http.Request, httpStatus int) ([]byte, error) {
	body, status, err := httpRequest(client, r)
	if err != nil {
		return body, err
	}

	if status != httpStatus {
		return nil, fmt.Errorf("unexpected http status code: %v with response %v", status, string(body))
	}
	return body, nil
}

func closeResponse(resp *http.Response) {
	if resp != nil && resp.Body != nil {
		_ = resp.Body.Close()
	}
}
