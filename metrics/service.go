package metrics

import (
	"github.com/mysteriumnetwork/openvpn-forwarder/proxy"
	"github.com/prometheus/client_golang/prometheus"
	"time"
)

var _ proxy.Listener = (*Service)(nil)

type Service struct {
	proxyRequestDuration              *prometheus.HistogramVec
	proxyNumberOfLiveConnecions       *prometheus.GaugeVec
	proxyNumberOfIncommingConnections *prometheus.CounterVec
	proxyNumberOfProcessedConnections *prometheus.CounterVec
}

func NewMetricsService() (*Service, error) {
	proxyRequestDuration := prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name: "proxy_request_duration",
		Help: "Proxy request duration in seconds",
	}, []string{"request_type"})

	if err := prometheus.Register(proxyRequestDuration); err != nil {
		return nil, err
	}

	proxyNumberOfLiveConnections := prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "proxy_number_of_live_connections",
		Help: "Number of currently live connections",
	}, []string{"request_type"})

	if err := prometheus.Register(proxyNumberOfLiveConnections); err != nil {
		return nil, err
	}

	proxyNumberOfIncommingConnections := prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "proxy_number_of_incomming_connections",
		Help: "Number of incomming connections (failed and successful)",
	}, []string{})

	if err := prometheus.Register(proxyNumberOfIncommingConnections); err != nil {
		return nil, err
	}

	proxyNumberOfProcessedConnections := prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "proxy_number_of_processed_connections",
		Help: "Number of incmming connections which were succesfully assigned and processed",
	}, []string{"request_type"})

	if err := prometheus.Register(proxyNumberOfProcessedConnections); err != nil {
		return nil, err
	}

	return &Service{
		proxyRequestDuration:              proxyRequestDuration,
		proxyNumberOfLiveConnecions:       proxyNumberOfLiveConnections,
		proxyNumberOfIncommingConnections: proxyNumberOfIncommingConnections,
		proxyNumberOfProcessedConnections: proxyNumberOfProcessedConnections,
	}, nil
}

func (s *Service) ProxyHandlerMiddleware(next func(c *proxy.Context), proxyHandlerType string) func(c *proxy.Context) {
	return func(c *proxy.Context) {
		startTime := time.Now()

		s.proxyNumberOfLiveConnecions.With(prometheus.Labels{
			"request_type": proxyHandlerType,
		}).Inc()

		next(c)

		s.proxyNumberOfLiveConnecions.With(prometheus.Labels{
			"request_type": proxyHandlerType,
		}).Dec()

		s.proxyRequestDuration.With(prometheus.Labels{
			"request_type": proxyHandlerType,
		}).Observe(time.Since(startTime).Seconds())

		s.proxyNumberOfProcessedConnections.With(prometheus.Labels{
			"request_type": proxyHandlerType,
		}).Inc()
	}
}

func (s *Service) OnProxyConnectionAccept() {
	s.proxyNumberOfIncommingConnections.With(prometheus.Labels{}).Inc()
}
