package main

import (
	"github.com/oschwald/geoip2-golang"
	"log/slog"
	"net"
	"sync"
)

type Geo struct {
	geoReader *geoip2.Reader
	mu        sync.Mutex
}

func NewGeo() *Geo {
	geo := &Geo{
		mu: sync.Mutex{},
	}
	// Try GeoLite2-Country.mmdb as a fallback name in addition to Country.mmdb
	reader, err := geoip2.Open("Country.mmdb")
	if err != nil {
		reader, err = geoip2.Open("GeoLite2-Country.mmdb")
	}
	if err != nil {
		slog.Warn("Cannot open Country.mmdb or GeoLite2-Country.mmdb")
		return geo
	}
	slog.Info("Enabled GeoIP")
	geo.geoReader = reader
	return geo
}

func (o *Geo) GetGeo(ip net.IP) string {
	if o.geoReader == nil {
		return "N/A"
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	country, err := o.geoReader.Country(ip)
	if err != nil {
		slog.Debug("Error reading geo", "err", err)
		return "N/A"
	}
	// Return "XX" for unknown country codes instead of empty string
	if country.Country.IsoCode == "" {
		return "XX"
	}
	return country.Country.IsoCode
}
