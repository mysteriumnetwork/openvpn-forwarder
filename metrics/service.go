package metrics

import (
	"github.com/mysteriumnetwork/openvpn-forwarder/proxy"
	"github.com/prometheus/client_golang/prometheus"
	"time"
)

type Service struct {
	proxyRequestDuration *prometheus.HistogramVec
	proxyRequestData     *prometheus.CounterVec
}

func NewMetricsService() (*Service, error) {
	proxyRequestDuration := prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name: "proxy_request_duration",
		Help: "Proxy request duration in seconds",
	}, []string{"request_type"})

	if err := prometheus.Register(proxyRequestDuration); err != nil {
		return nil, err
	}

	proxyRequestData := prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "proxy_request_data",
		Help: "Proxy request data in bytes",
	}, []string{"request_type", "direction"})

	if err := prometheus.Register(proxyRequestData); err != nil {
		return nil, err
	}

	return &Service{
		proxyRequestDuration: proxyRequestDuration,
		proxyRequestData:     proxyRequestData,
	}, nil
}

func (s *Service) ProxyMiddleware(next func(c *proxy.Context), proxyHandlerType string) func(c *proxy.Context) {
	return func(c *proxy.Context) {
		startTime := time.Now()

		next(c)

		s.proxyRequestDuration.With(prometheus.Labels{
			"request_type": proxyHandlerType,
		}).Observe(time.Since(startTime).Seconds())

		s.proxyRequestData.With(prometheus.Labels{
			"request_type": proxyHandlerType,
			"direction":    "sent",
		}).Add(float64(c.BytesSent()))

		s.proxyRequestData.With(prometheus.Labels{
			"request_type": proxyHandlerType,
			"direction":    "received",
		}).Add(float64(c.BytesReceived()))
	}
}
