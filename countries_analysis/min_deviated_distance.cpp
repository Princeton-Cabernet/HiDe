#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <random>
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

// Compute min F = d(S,A) + d(D,A) - d(S,D) over pts1×pts1×pts2 (variant0)
// Returns (bestF, S, D, A_orig, idxA)
std::tuple<double,double,double,GeoPt,GeoPt,GeoPt,double,double,double,size_t>
computeMinF(const std::vector<GeoPt>& pts1,
            const std::vector<GeoPt>& pts2)
{
    double bestF = std::numeric_limits<double>::infinity();
    double best_pre = std::numeric_limits<double>::infinity();
    double best_post = std::numeric_limits<double>::infinity();
    double best_dSD = std::numeric_limits<double>::infinity();
    double best_dSA = std::numeric_limits<double>::infinity();
    double best_dDA = std::numeric_limits<double>::infinity();
    GeoPt bestS{0,0}, bestD{0,0}, bestA{0,0};
    size_t bestIdxA = 0;
    size_t n1 = pts1.size(), n2 = pts2.size();

    for (size_t i1 = 0; i1 < n1; ++i1) {
        for (size_t i2 = i1; i2 < n1; ++i2) {
            double dSD = geodesicDistance(pts1[i1], pts1[i2]);
            double d_pre = 2 * dSD;
            for (size_t j = 0; j < n2; ++j) {
                double dSA = geodesicDistance(pts1[i1], pts2[j]);
                double dDA = geodesicDistance(pts1[i2], pts2[j]);
                double d_post = dSD + dSA + dDA;
                double F   = d_post - d_pre;
                if (F < bestF) {
                    bestF    = F;
                    best_pre = d_pre;
                    best_post = d_post;
                    bestS    = pts1[i1];
                    bestD    = pts1[i2];
                    bestA    = pts2[j];
                    best_dSD = dSD;
                    best_dSA = dSA;
                    best_dDA = dDA;
                    bestIdxA = j;
                }
            }
        }
    }
    return {bestF, best_pre, best_post, bestS, bestD, bestA, best_dSD, best_dSA, best_dDA, bestIdxA};
}

// Of the three variants at index idx2, pick the one whose (lat,lon)
// is closest in simple Euclidean space to ref.
GeoPt findShiftedPointEuc(
    const GeoPt& S,
    const GeoPt& D,
    const std::vector<std::vector<GeoPt>>& variants,
    size_t idxA)
{
    auto euclid = [&](const GeoPt& X, const GeoPt& Y) {
        double dx = X.lat - Y.lat;
        double dy = X.lon - Y.lon;
        return std::sqrt(dx*dx + dy*dy);
    };

    double bestScore = std::numeric_limits<double>::infinity();
    GeoPt  bestPt{0,0};

    // precompute dSD once (constant offset)
    double dSD = euclid(S, D);

    for (int v = 0; v < 3; ++v) {
        if (idxA >= variants[v].size()) continue;
        const GeoPt& A = variants[v][idxA];
        // compute F_euc(S,D;A) = d(S,A) + d(D,A) - d(S,D)
        double score = euclid(S, A) + euclid(D, A) - dSD;
        if (score < bestScore) {
            bestScore = score;
            bestPt    = A;
        }
    }
    return bestPt;
}

// Write the results (country, max-distance, lat1, lon1, lat2, lon2) to a CSV file
void writeResultsCSV(
    const std::string &fname,
    const std::vector<
      std::tuple<std::string,  // country1
                 std::string,  // country2
                 double, double, double, // F_km, pre_km, post_km
                 GeoPt, GeoPt, GeoPt, // S, D, A (shifted)
                 double, double, double // dSD, dSA, dDA
        >>& results)
  {
    std::ofstream ofs(fname);
    ofs<<"Country1,Country2,"
        "MinDeviation_km,PreAttack_km,PostAttack_km,"
        "Dist_SD_km,Dist_SA_km,Dist_DA_km,"
        "S_lat,S_lon,D_lat,D_lon,"
        "A_lat,A_lon\n";
    for (auto &rec : results) {
        auto &[c1,c2,F,pre,post,S,D,Ash,dSD,dSA,dDA] = rec;
        ofs<<c1<<','<<c2<<','
            <<F<<','<<pre<<','<<post<<','
            <<dSD<<','<<dSA<<','<<dDA<<','
            <<S.lat<<','<<S.lon<<','
            <<D.lat<<','<<D.lon<<','
            <<Ash.lat<<','<<Ash.lon<<"\n";
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
    
    size_t N = vec.size();
    std::vector<std::tuple<std::string,
                           std::string,
                           double, double, double,
                           GeoPt, GeoPt, GeoPt,
                           double, double, double>> results;
    results.reserve(N * (N - 1));

    // Determine minimum distances for pairs of countries (i<j)
    std::cout << "Computing minimum diverted distances...\n";
    size_t pair_count = 0;

    // Parallel over ALL ordered pairs (i != j)
    #pragma omp parallel for collapse(2) schedule(dynamic) num_threads(100)
    for (size_t i = 0; i < N; ++i) {
        for (size_t j = 0; j < N; ++j) {
            if (i == j) continue;

            auto& [c1, v1] = vec[i];
            auto& [c2, v2] = vec[j];
            auto& pts1 = v1[0];
            auto& pts2 = v2[0];

            // compute best (S,D,A,idxA)
            auto [F,pre,post,S,D,A,dSD,dSA,dDA,idxA] = computeMinF(pts1, pts2);

            // choose shifted A for plotting
            GeoPt Ash = findShiftedPointEuc(S, D, v2, idxA);

            auto rec = std::make_tuple(
                c1, c2, F, pre, post, S, D, Ash, dSD, dSA, dDA
            );

            #pragma omp critical
            {
                results.push_back(rec);
                ++pair_count;
                if (pair_count % 1000 == 0) {
                    std::cout<< pair_count <<" country-pairs processed out of " << N * (N - 1) << "\n";
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
