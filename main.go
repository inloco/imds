package main

import (
	"encoding/json"
	"errors"
	"flag"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/iam"
	"github.com/aws/aws-sdk-go/service/sts"
	"github.com/julienschmidt/httprouter"
)

var (
	stsClient = sts.New(session.New())
	iamClient = iam.New(session.New())
)

func getUserId() (string, error) {
	callerIdentity, err := stsClient.GetCallerIdentity(&sts.GetCallerIdentityInput{})
	if err != nil {
		return "", err
	}
	userId := aws.StringValue(callerIdentity.UserId)

	return userId, nil
}

func getRoleName(principalId string) (string, error) {
	if principalId[:4] != "AROA" {
		return "", nil
	}

	var roleName string
	fn := func(page *iam.ListRolesOutput, lastPage bool) bool {
		for _, role := range page.Roles {
			if aws.StringValue(role.RoleId) == principalId {
				roleName = aws.StringValue(role.RoleName)
				return false
			}
		}

		return true
	}

	if err := iamClient.ListRolesPages(&iam.ListRolesInput{}, fn); err != nil {
		return "", err
	}
	if roleName == "" {
		return "", errors.New(iam.ErrCodeNoSuchEntityException)
	}

	return roleName, nil
}

type credentialsProvider func() (*sts.Credentials, error)

func sessionToken() (credentialsProvider, error) {
	provider := func() (*sts.Credentials, error) {
		out, err := stsClient.GetSessionToken(&sts.GetSessionTokenInput{})
		if err != nil {
			return nil, err
		}

		return out.Credentials, nil
	}
	return provider, nil
}

func assumeRole(roleName string, sessionName string) (credentialsProvider, error) {
	getRoleInput := &iam.GetRoleInput{
		RoleName: aws.String(roleName),
	}
	role, err := iamClient.GetRole(getRoleInput)
	if err != nil {
		return nil, err
	}

	provider := func() (*sts.Credentials, error) {
		out, err := stsClient.AssumeRole(&sts.AssumeRoleInput{
			RoleArn:         role.Role.Arn,
			RoleSessionName: aws.String(sessionName),
		})
		if err != nil {
			return nil, err
		}

		return out.Credentials, nil
	}
	return provider, nil
}

type credentialsResponse struct {
	Code            string
	LastUpdated     time.Time
	Type            string
	AccessKeyId     string
	SecretAccessKey string
	Token           string
	Expiration      time.Time
}

func credentialsHandler(provider credentialsProvider) httprouter.Handle {
	return func(w http.ResponseWriter, _ *http.Request, _ httprouter.Params) {
		credentials, err := provider()
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		res := &credentialsResponse{
			Code:            "Success",
			LastUpdated:     time.Now().In(time.UTC).Round(time.Second),
			Type:            "AWS-HMAC",
			AccessKeyId:     aws.StringValue(credentials.AccessKeyId),
			SecretAccessKey: aws.StringValue(credentials.SecretAccessKey),
			Token:           aws.StringValue(credentials.SessionToken),
			Expiration:      aws.TimeValue(credentials.Expiration),
		}
		if err := json.NewEncoder(w).Encode(res); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
	}
}

func staticHandler(body string) httprouter.Handle {
	return func(w http.ResponseWriter, _ *http.Request, _ httprouter.Params) {
		w.Write([]byte(body))
	}
}

func start(roleName string, lstnAddr string) error {
	log.Print("initializing IMDS")

	userId, err := getUserId()
	if err != nil {
		return err
	}
	principalId := strings.Split(userId, ":")[0]
	sessionName := userId[strings.Index(userId, ":")+1:]

	if roleName == "" {
		rn, err := getRoleName(principalId)
		if err != nil {
			return err
		}

		roleName = rn
	}

	var provider credentialsProvider
	switch roleName {
	case "":
		provider, err = sessionToken()
	default:
		provider, err = assumeRole(roleName, sessionName)
	}
	if err != nil {
		return err
	}

	router := httprouter.New()
	router.PUT("/:version/api/token", staticHandler(""))
	router.GET("/:version/meta-data/iam/security-credentials/", staticHandler(roleName))
	router.GET("/:version/meta-data/iam/security-credentials/:role", credentialsHandler(provider))

	log.Printf("listening %s", lstnAddr)
	return http.ListenAndServe(lstnAddr, router)
}

func main() {
	roleFlag := flag.String("roleName", "", "")
	addrFlag := flag.String("lstnAddr", "169.254.169.254:80", "")
	flag.Parse()

	log.Panic(start(*roleFlag, *addrFlag))
}
