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

// Struct to store victim country, local lat/lon, and remote lat/lon
struct Prefix {
    std::string victim;
    GeoPt local;
    GeoPt remote;
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

// Parse the JSON file into a map: prefix → vector of points (src, dst)
bool parsePrefixes(const std::string& filename,
                    std::map<std::string, Prefix>& out) 
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

    // Iterate over each prefix in the JSON object and extract the data into a Prefix struct
    for (auto& [prefix, arr] : j.items()) {
        if (!arr.is_array() || arr.size() != 3) continue;

        if (arr[0].is_string() && arr[1].is_array() && arr[2].is_array()) {
            std::string country = arr[0].get<std::string>();
            GeoPt local = { arr[1][0].get<double>(), arr[1][1].get<double>() };
            GeoPt remote = { arr[2][0].get<double>(), arr[2][1].get<double>() };
            out.emplace(prefix, Prefix{ country, local, remote });
        }
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
computeMinF(const GeoPt& S, const GeoPt& D,
            const std::vector<GeoPt>& attack_coordinates)
{
    // Known distances
    double dSD = geodesicDistance(S, D);
    double pre = 2 * dSD;
    
    // Initialize unknown distances
    double bestF = std::numeric_limits<double>::infinity();
    double best_post = std::numeric_limits<double>::infinity();
    double best_dSA = std::numeric_limits<double>::infinity();
    double best_dDA = std::numeric_limits<double>::infinity();

    GeoPt bestA{0,0};
    size_t bestIdxA = 0;
    size_t N = attack_coordinates.size();

    for (size_t i = 0; i < N; ++i) {
        double dSA = geodesicDistance(S, attack_coordinates[i]);
        double dDA = geodesicDistance(D, attack_coordinates[i]);
        double post = dSD + dSA + dDA;
        double F = post - pre;
        if (F < bestF) {
            bestF     = F;
            best_post = post;
            bestA     = attack_coordinates[i];
            best_dSA  = dSA;
            best_dDA  = dDA;
            bestIdxA  = i;
        }
    }
    return {bestF, pre, best_post, S, D, bestA, dSD, best_dSA, best_dDA, bestIdxA};
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
      std::tuple<std::string,  // prefix
                 std::string,  // attacker country
                 double, double, double, // F_km, pre_km, post_km
                 GeoPt, GeoPt, GeoPt, // S, D, A (shifted)
                 double, double, double // dSD, dSA, dDA
        >>& results)
  {
    std::ofstream ofs(fname);
    ofs<<"Prefix,Attacker,"
        "MinDeviation_km,PreAttack_km,PostAttack_km,"
        "Dist_SD_km,Dist_SA_km,Dist_DA_km,"
        "S_lat,S_lon,D_lat,D_lon,"
        "A_lat,A_lon\n";
    for (auto &rec : results) {
        auto &[p,c,F,pre,post,S,D,Ash,dSD,dSA,dDA] = rec;
        ofs<<p<<','<<c<<','
            <<F<<','<<pre<<','<<post<<','
            <<dSD<<','<<dSA<<','<<dDA<<','
            <<S.lat<<','<<S.lon<<','
            <<D.lat<<','<<D.lon<<','
            <<Ash.lat<<','<<Ash.lon<<"\n";
    }
  }

int main(int argc, char* argv[]) {
    const std::string path_prefix = "/media/data/satadals/p4-measurements/attack_detection/campus_trace_analysis/ipynb/";
    if (argc < 4) {
        std::cerr << "Usage: " << argv[0] << " [json_country_file] [json_prefix_file] [csv_file]\n";
        return 1;
    }

    const std::string jsonFileCountry = path_prefix + argv[1];
    const std::string jsonFilePrefix = path_prefix + argv[2];
    const std::string csvFile  = path_prefix + argv[3];
    std::cout << "Using JSON file (country): " << argv[1] << "\n";
    std::cout << "Using JSON file (prefix): " << argv[2] << "\n";
    std::cout << "Outputting results to: " << argv[3] << "\n";

    // Load sampled and shifted country coordinates from JSON
    std::map<std::string, std::vector<std::vector<GeoPt>>> countryVars;
    if (!parseCountryVariants(jsonFileCountry, countryVars))
        return 1;

    // Load prefix coordinates from JSON
    std::map<std::string, Prefix> prefixCoords;
    if (!parsePrefixes(jsonFilePrefix, prefixCoords))
        return 1;

    // Move into a vector for indexed loops
    std::vector<std::pair<std::string,
        std::vector<std::vector<GeoPt>>>> vecCountry;
    vecCountry.reserve(countryVars.size());
    for (auto& kv : countryVars)
        vecCountry.emplace_back(kv.first, std::move(kv.second));
    
    // Move into a vector for indexed loops
    std::vector<std::pair<std::string,
        Prefix>> vecPrefix;
    vecPrefix.reserve(prefixCoords.size());
    for (auto& kv : prefixCoords)
        vecPrefix.emplace_back(kv.first, std::move(kv.second));
    
    size_t C = vecCountry.size();
    size_t P = vecPrefix.size();
    std::vector<std::tuple<std::string,
                           std::string,
                           double, double, double,
                           GeoPt, GeoPt, GeoPt,
                           double, double, double>> results;
    results.reserve(P * (C - 1));

    std::cout << C << " countries and " << P
              << " prefixes loaded.\n";

    // Determine minimum distances for pairs of prefixes and countries
    std::cout << "Computing minimum diverted distances...\n";
    size_t pair_count = 0;

    // Parallel over ALL ordered pairs (i != j)
    #pragma omp parallel for collapse(2) schedule(dynamic) num_threads(100)
    for (size_t p = 0; p < P; ++p) {
        for (size_t c = 0; c < C; ++c) {

            auto& [prefix, pObj] = vecPrefix[p];
            auto& [attacker, cObj] = vecCountry[c];

            // Skip if prefix's victim country and adversary country are the same
            if (pObj.victim == attacker) continue;

            auto& S_victim = pObj.local;
            auto& D_victim = pObj.remote;
            auto& attackCoords = cObj[0];

            // Compute optimal attack point A
            auto [F,pre,post,S,D,A,dSD,dSA,dDA,idxA] = computeMinF(S_victim, D_victim, attackCoords);

            // Choose shifted A for plotting
            GeoPt Ash = findShiftedPointEuc(S, D, cObj, idxA);

            auto rec = std::make_tuple(
                prefix, attacker, F, pre, post, S, D, Ash, dSD, dSA, dDA
            );

            #pragma omp critical
            {
                results.push_back(rec);
                ++pair_count;
                if (pair_count % 1000000 == 0) {
                    std::cout<< pair_count <<" prefix-country pairs processed out of " << P * (C - 1) << "\n";
                }
            }
        }
    }

    // Sort results by prefix, then attacker country
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
