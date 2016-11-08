package main

import (
	"crypto/tls"
	"fmt"
	"github.com/BurntSushi/toml"
	log "github.com/Sirupsen/logrus"
	dockerapi "github.com/docker/docker/api"
	dockerclient "github.com/docker/engine-api/client"
	"github.com/docker/go-plugins-helpers/authorization"
	"net/http"
	"net/url"
	"path/filepath"
	"regexp"
)

func newPlugin(dockerHost, certPath string, tlsVerify bool) (*novolume, error) {
	var transport *http.Transport
	if certPath != "" {
		tlsc := &tls.Config{}

		cert, err := tls.LoadX509KeyPair(filepath.Join(certPath, "cert.pem"), filepath.Join(certPath, "key.pem"))
		if err != nil {
			return nil, fmt.Errorf("Error loading x509 key pair: %s", err)
		}

		tlsc.Certificates = append(tlsc.Certificates, cert)
		tlsc.InsecureSkipVerify = !tlsVerify
		transport = &http.Transport{
			TLSClientConfig: tlsc,
		}
	}

	client, err := dockerclient.NewClient(dockerHost, dockerapi.DefaultVersion.String(), transport, nil)
	if err != nil {
		return nil, err
	}
	return &novolume{client: client}, nil
}

var (
	startRegExp = regexp.MustCompile(`/containers/(.*)/start`)
)

type novolume struct {
	client *dockerclient.Client
}

/***********************************
* TOML corresponding structures
***********************************/

type container struct {
	Name string
}

type containers struct {
	Container []container
}

/**** END TOML structures ****/

func (p *novolume) AuthZReq(req authorization.Request) authorization.Response {
	ruri, err := url.QueryUnescape(req.RequestURI)
	if err != nil {
		return authorization.Response{Err: err.Error()}
	}
	if req.RequestMethod == "POST" && startRegExp.MatchString(ruri) {
		/* capture containers at start call */
		res := startRegExp.FindStringSubmatch(ruri)
		if len(res) < 1 {
			return authorization.Response{Err: "unable to find container name"}
		}

		/* Read the TOML configuration file */
		var cnames containers
		if _, err := toml.DecodeFile("/home/vagrant/config.toml", &cnames); err != nil {
			log.Info(cnames)
			//return authorization.Response{Err: err.Error()}
		}

		/* Inspect container */
		container, err := p.client.ContainerInspect(res[1])
		if err != nil {
			return authorization.Response{Err: err.Error()}
		}

		log.Info("Container name: " + container.Name[1:])

		for _, c := range cnames.Container {
			if container.Name[1:] == c.Name {
				log.Info("Exception done for " + c.Name + " , container in the whitelist file")
				return authorization.Response{Allow: true}
			}
		}

		/* Check running container user (if its not ROOT) */
		if container.Config.User == "" {
			goto noallow
		}

		image, _, err := p.client.ImageInspectWithRaw(container.Image, false)

		if err != nil {
			return authorization.Response{Err: err.Error()}
		}

		/* check if the image has a privileged user (ROOT) */

		if image.ContainerConfig.User == "" {
			goto noallow
		}

	}
	return authorization.Response{Allow: true}

noallow:
	return authorization.Response{Msg: "Root User is not allowed inside containers"}
}

func (p *novolume) AuthZRes(req authorization.Request) authorization.Response {
	return authorization.Response{Allow: true}
}
