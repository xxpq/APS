package charts

import (
	"log"
	"time"

	// "tata/lib/charts/bindata"

	"aps/charts/bindata"
	"aps/charts/metrics"
	"aps/charts/metrics/exp"

	_ "expvar"
	"net/http"
	_ "net/http/pprof"
)

var mtx = metrics.NewRegistry()

func Register(mux *http.ServeMux) {

	metrics.RegisterDebugGCStats(mtx)
	go metrics.CaptureDebugGCStats(mtx, time.Second*5)

	metrics.RegisterRuntimeMemStats(mtx)
	go metrics.CaptureRuntimeMemStats(mtx, time.Second*5)

	exp.Exp(mtx, mux)

	mux.HandleFunc("/debug/metrics/charts/", handleAsset("static/index.html"))
	mux.HandleFunc("/debug/metrics/charts/main.js", handleAsset("static/main.js"))
	mux.HandleFunc("/debug/metrics/charts/plotly.js", handleAsset("static/plotly.js"))
}

func handleAsset(path string) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		data, err := bindata.Asset(path)
		if err != nil {
			log.Print(err)
			return
		}

		n, err := w.Write(data)
		if err != nil {
			log.Print(err)
			return
		}

		if n != len(data) {
			log.Print("wrote less than supposed to")
			return
		}
	}
}
