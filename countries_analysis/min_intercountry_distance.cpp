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

// 1) Parse JSON into map<country, vector<3 variant‐vectors>>
bool parseCountryVariants(
    const std::string& filename,
    std::map<std::string, std::vector<std::vector<GeoPt>>>& out)
{
    std::ifstream ifs(filename);
    if (!ifs) {
        std::cerr << "Cannot open " << filename << "\n";
        return false;
    }
    json j;
    try { ifs >> j; }
    catch (const json::parse_error& e) {
        std::cerr << "JSON parse error: " << e.what() << "\n";
        return false;
    }
    if (!j.is_object()) {
        std::cerr << "Top‐level JSON is not an object\n";
        return false;
    }

    for (auto& [country, arr3] : j.items()) {
        if (!arr3.is_array() || arr3.size() != 3) continue;
        std::vector<std::vector<GeoPt>> variants(3);
        for (int v = 0; v < 3; ++v) {
            auto& arr = arr3[v];
            if (!arr.is_array()) continue;
            for (auto& pt : arr) {
                if (pt.is_array() && pt.size() == 2
                    && pt[0].is_number() && pt[1].is_number())
                {
                    variants[v].push_back({
                      pt[0].get<double>(),
                      pt[1].get<double>()
                    });
                }
            }
        }
        out.emplace(country, std::move(variants));
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
// Returns (minDist, pt1_on_country1, pt2_on_country2, idx2)
std::tuple<double, GeoPt, GeoPt, size_t>
computeMinInterCountryDistance(
    const std::vector<GeoPt>& pts1,
    const std::vector<GeoPt>& pts2)
{
    double best = std::numeric_limits<double>::infinity();
    GeoPt bestA{0,0}, bestB{0,0};
    size_t bestIdx2 = 0;
    for (size_t i = 0; i < pts1.size(); ++i) {
        for (size_t j = 0; j < pts2.size(); ++j) {
            double d = geodesicDistance(pts1[i], pts2[j]);
            if (d < best) {
                best = d;
                bestA = pts1[i];
                bestB = pts2[j];
                bestIdx2 = j;
            }
        }
    }
    return {best, bestA, bestB, bestIdx2};
}

// Of the three variants at index idx2, pick the one whose (lat,lon)
// is closest in simple Euclidean space to ref.
GeoPt findShiftedPoint(
    const GeoPt& ref,
    const std::vector<std::vector<GeoPt>>& variants,
    size_t idx2)
{
    double bestSq = std::numeric_limits<double>::infinity();
    GeoPt bestPt{0,0};
    for (int v = 0; v < 3; ++v) {
        // guard in case variant lengths differ
        if (idx2 >= variants[v].size()) continue;
        const GeoPt& p = variants[v][idx2];
        double dx = p.lat  - ref.lat;
        double dy = p.lon  - ref.lon;
        double sq = dx*dx + dy*dy;
        if (sq < bestSq) {
            bestSq = sq;
            bestPt = p;
        }
    }
    return bestPt;
}

// Write the results (country, max-distance, lat1, lon1, lat2, lon2) to a CSV file
void writeResultsCSV(
    const std::string& fname,
    const std::vector<
      std::tuple<std::string, // country1
                 std::string, // country2
                 double,      // minDistance
                 GeoPt,       // Lat1/Lon1
                 GeoPt        // Lat_shifted_2/Lon_shifted_2
      >>& results)
{
    std::ofstream ofs(fname);
    ofs << "Country1,Country2,MinDistance_km,"
           "Lat1,Lon1,Lat2,Lon2\n";
    for (auto& rec : results) {
        auto& [c1,c2,d,p1,ps] = rec;
        ofs
          << c1 << ',' 
          << c2 << ',' 
          << d  << ','
          << p1.lat << ',' 
          << p1.lon << ','
          << ps.lat << ','
          << ps.lon << "\n";
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

    // Load sampled and shifted country coordinates from JSON
    std::map<std::string, std::vector<std::vector<GeoPt>>> countryVars;
    if (!parseCountryVariants(jsonFile, countryVars))
        return 1;

    // Move into a vector for indexed loops
    std::vector<std::pair<std::string,
        std::vector<std::vector<GeoPt>>>> vec;
    vec.reserve(countryVars.size());
    for (auto& kv : countryVars)
        vec.emplace_back(kv.first, std::move(kv.second));
    
    // // Print indices and country names
    // std::cout << "Countries loaded: " << vec.size() << "\n";
    // for (size_t i = 0; i < vec.size(); ++i) {
    //     std::cout << "Index " << i << ": " << vec[i].first << "\n";
    // }

    size_t N = vec.size();
    std::vector<std::tuple<std::string,
                           std::string,
                           double,
                           GeoPt,
                           GeoPt>> results;
    results.reserve(N*(N-1)/2);

    // Determine minimum distances for pairs of countries (i<j)
    std::cout << "Computing minimum inter-country distances...\n";
    size_t pair_count = 0;
    const int total_pairs = N * (N - 1) / 2;

    // Parallel outer loop with 100 threads
    #pragma omp parallel for schedule(dynamic) num_threads(100)
    for (int ii = 0; ii < (int)N; ++ii) {
        size_t i = ii;
        for (size_t j = i+1; j < N; ++j) {
            auto& [c1, v1] = vec[i];
            auto& [c2, v2] = vec[j];
            auto& pts1 = v1[0];
            auto& pts2 = v2[0];

            // compute geodesic minimum & idx2
            auto [minD, anchor, orig2, idx2] =
              computeMinInterCountryDistance(pts1, pts2);

            // find shifted point among variants at idx2
            GeoPt shifted2 = findShiftedPoint(anchor, v2, idx2);

            auto rec1 = std::make_tuple(
              c1, c2, minD, anchor, shifted2
            );
            auto rec2 = std::make_tuple(
              c2, c1, minD, shifted2, anchor
            );

            // store result & update counter in critical section
            #pragma omp critical
            {
                results.push_back(rec1);
                results.push_back(rec2);
                ++pair_count;
                if (pair_count % 1000 == 0) {
                    std::cout << pair_count << " country-pairs processed"
                              << " out of " << total_pairs << " pairs\n";
                }
            }
        }
    }

    // Sort results by country1, then country2
    std::sort(results.begin(), results.end(),
      [](auto const &a, auto const &b){
        const auto& c1a = std::get<0>(a);
        const auto& c1b = std::get<0>(b);
        if (c1a != c1b) return c1a < c1b;
        return std::get<1>(a) < std::get<1>(b);
      }
    );

    writeResultsCSV(csvFile, results);
    std::cout << "Wrote " << results.size()
              << " country-pairs to " << argv[2] << "\n";

    return 0;
}
