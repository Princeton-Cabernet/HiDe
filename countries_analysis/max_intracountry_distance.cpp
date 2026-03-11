#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <map>
#include <algorithm>    // for std::max
#include <atomic>       // for std::atomic
#include <omp.h>        // for OpenMP

// nlohmann::json single-header library
#include "nlohmann_json.hpp"
using json = nlohmann::json;

// GeographicLib for ellipsoidal geodesic computations
#include <GeographicLib/Geodesic.hpp>
using namespace GeographicLib;

// simple struct to hold latitude/longitude
struct GeoPt {
    double lat;
    double lon;
};

// Parse the JSON file into a map: country → vector of points
bool parseCountries(const std::string& filename,
                    std::map<std::string, std::vector<GeoPt>>& out) 
{
    std::ifstream ifs(filename);
    if (!ifs) {
        std::cerr << "Error: cannot open " << filename << "\n";
        return false;
    }

    json j;
    try {
        ifs >> j;
    } catch (const json::parse_error& e) {
        std::cerr << "Parse error: " << e.what() << "\n";
        return false;
    }

    if (!j.is_object()) {
        std::cerr << "Error: top-level JSON is not an object\n";
        return false;
    }

    for (auto& [country, arr] : j.items()) {
        if (!arr.is_array()) continue;
        std::vector<GeoPt> pts;
        pts.reserve(arr.size());

        for (auto& pt : arr) {
            if (pt.is_array() && pt.size() == 2
                && pt[0].is_number() && pt[1].is_number())
            {
                pts.push_back({ pt[0].get<double>(),
                                pt[1].get<double>() });
            }
        }
        out.emplace(country, std::move(pts));
    }
    return true;
}

// Compute ellipsoidal distance (km) between two points using GeographicLib
double geodesicDistance(const GeoPt& a, const GeoPt& b) {
    static const Geodesic& geo = Geodesic::WGS84();
    double s12;
    geo.Inverse(a.lat, a.lon, b.lat, b.lon, s12);
    return s12 / 1000.0;
}

// Compute the maximum pairwise geodesic distance within a set of points.
// Returns: (maxDistance_km, pointA, pointB)
std::tuple<double, GeoPt, GeoPt>
computeMaxDistance(const std::vector<GeoPt>& pts) {
    double local_max = 0.0;
    GeoPt bestA{0,0}, bestB{0,0};
    size_t n = pts.size();
    for (size_t i = 0; i < n; ++i) {
        for (size_t j = i + 1; j < n; ++j) {
            double d = geodesicDistance(pts[i], pts[j]);
            if (d > local_max) {
                local_max = d;
                bestA = pts[i];
                bestB = pts[j];
            }
        }
    }
    return {local_max, bestA, bestB};
}

// Write the results (country, max-distance, lat1, lon1, lat2, lon2) to a CSV file
void writeResultsCSV(
    const std::string& filename,
    const std::vector<std::tuple<std::string,double,GeoPt,GeoPt>>& results)
{
    std::ofstream ofs(filename);
    if (!ofs) {
        std::cerr << "Error: cannot open output file " << filename << "\n";
        return;
    }

    // CSV header
    ofs << "Country,MaxDistance_km,Lat1,Lon1,Lat2,Lon2\n";
    for (auto const& rec : results) {
        const auto& [country, dist, p1, p2] = rec;
        ofs
          << country << ","
          << dist    << ","
          << p1.lat  << ","
          << p1.lon  << ","
          << p2.lat  << ","
          << p2.lon  << "\n";
    }
}

int main(int argc, char* argv[]) {
    const std::string path_prefix = "/media/data/satadals/p4-measurements/attack_detection/campus_trace_analysis/ipynb/";
    if (argc < 3) {
        std::cerr << "Usage: " << argv[0] << " [json_file] [csv_file]\n";
        return 1;
    }
    const std::string jsonFile = path_prefix + argv[1];
    const std::string csvFile  = path_prefix + argv[2];
    std::cout << "Using JSON file: " << argv[1] << "\n";
    std::cout << "Outputting results to: " << argv[2] << "\n";

    // 1) Parse JSON
    std::map<std::string, std::vector<GeoPt>> countries;
    if (!parseCountries(jsonFile, countries)) {
        return 1;
    }

    // 2) Move into a vector for indexed access
    std::vector<std::pair<std::string,std::vector<GeoPt>>> vec;
    vec.reserve(countries.size());
    for (auto& kv : countries) {
        vec.emplace_back(kv.first, std::move(kv.second));
    }

    size_t M = vec.size();
    std::vector<std::tuple<double,GeoPt,GeoPt>> maxInfo(M);

    // Counter for progress
    int done_count = 0;

    // 3) Compute max distances per country
    #pragma omp parallel for schedule(dynamic) num_threads(100)
    for (int i = 0; i < (int)M; ++i) {
        std::tuple<double,GeoPt,GeoPt> result = computeMaxDistance(vec[i].second);

        #pragma omp critical
        {    
            maxInfo[i] = result;
            ++done_count; // atomic increment
            if (done_count % 25 == 0) {
                std::cout << done_count << " countries processed\n";
            }
        }
    }

    // 4) Print to stdout and collect results
    std::vector<std::tuple<std::string,double,GeoPt,GeoPt>> results;
    results.reserve(M);
    for (size_t i = 0; i < M; ++i) {
        const auto& country = vec[i].first;
        auto [dist, p1, p2] = maxInfo[i];
        // std::cout
        //     << i + 1 << ": "
        //     << country << ": "
        //     << dist << " km "
        //     << "(" << p1.lat << "," << p1.lon << ")"
        //     << " ↔ "
        //     << "(" << p2.lat << "," << p2.lon << ")"
        //     << "\n";
        results.emplace_back(country, dist, p1, p2);
    }

    // 5) Write to CSV
    writeResultsCSV(csvFile, results);
    std::cout << "Done\n";

    return 0;
}
