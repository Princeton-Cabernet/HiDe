#include <gdal/ogrsf_frmts.h>
#include <GeographicLib/Geodesic.hpp>
#include <fstream>
#include <vector>
#include <limits>
#include <random>
#include <iostream>
#include <iomanip>
#include <omp.h>

using namespace GeographicLib;

struct Result {
    std::string homeCountry;
    std::string threatCountry;
    OGRPoint optimal_S;
    OGRPoint optimal_D;
    OGRPoint optimal_A;
    double dist_SD;
    double dist_SA;
    double dist_DA;
    double F_value;
};

std::vector<OGRPoint> samplePointsInside(OGRGeometry* geom, double scale, int samples_per_axis) {
    std::vector<OGRPoint> points;
    OGREnvelope envelope;
    geom->getEnvelope(&envelope);

    double x_step = (envelope.MaxX - envelope.MinX) / samples_per_axis;
    double y_step = (envelope.MaxY - envelope.MinY) / samples_per_axis;

    for (double x = envelope.MinX; x <= envelope.MaxX; x += x_step * scale) {
        for (double y = envelope.MinY; y <= envelope.MaxY; y += y_step * scale) {
            OGRPoint pt(x, y);
            if (geom->Contains(&pt)) {
                points.push_back(pt);
            }
        }
    }
    return points;
}

double computeDistance(const OGRPoint& p1, const OGRPoint& p2, const Geodesic& geod) {
    double s12;
    geod.Inverse(p1.getY(), p1.getX(), p2.getY(), p2.getX(), s12);
    return s12 / 1000.0; // km
}

int main() {
    GDALAllRegister();
    const Geodesic& geod = Geodesic::WGS84();

    const char* shapefile = "/u/satadals/local/geolocation_based_analysis/data/ne_10m_admin_0_countries.shp";
    GDALDataset* dataset = (GDALDataset*) GDALOpenEx(shapefile, GDAL_OF_VECTOR, nullptr, nullptr, nullptr);
    if (!dataset) {
        std::cerr << "Failed to open shapefile.\n";
        return 1;
    }

    OGRLayer* layer = dataset->GetLayer(0);

    std::vector<std::pair<std::string, OGRGeometry*>> countries;
    OGRFeature* feature;
    layer->ResetReading();
    while ((feature = layer->GetNextFeature()) != nullptr) {
        const char* name = feature->GetFieldAsString("ADMIN");
        OGRGeometry* geom = feature->GetGeometryRef()->clone();
        countries.emplace_back(name, geom);
        OGRFeature::DestroyFeature(feature);
    }
    countries.resize(3); // limit to 5 countries for testing

    std::vector<Result> results;

    #pragma omp parallel for schedule(dynamic)
    for (size_t home_idx = 0; home_idx < countries.size(); ++home_idx) {
        const auto& home = countries[home_idx];

        std::vector<Result> local_results;

        for (const auto& threat : countries) {

            #pragma omp critical
            {
                std::cout << "Processing Home country: " << home.first << ", Threat country: " << threat.first << std::endl;
            }
            
            if (home.first == threat.first) continue;

            double scale = 1.0;
            double min_F = std::numeric_limits<double>::max();
            Result best_result;
            int local_count = 0;

            for (int iteration = 0; iteration < 1000; ++iteration) {
                auto home_points = samplePointsInside(home.second, scale, 10);
                auto threat_points = samplePointsInside(threat.second, scale, 10);

                for (size_t i = 0; i < home_points.size(); ++i) {
                    const auto& S = home_points[i];
                    for (size_t j = i + 1; j < home_points.size(); ++j) {
                        const auto& D = home_points[j];
                        double dist_SD = computeDistance(S, D, geod);

                        for (const auto& A : threat_points) {
                            local_count++;
                            double dist_SA = computeDistance(S, A, geod);
                            double dist_DA = computeDistance(D, A, geod);
                            double F = dist_SA + dist_DA - dist_SD;

                            if (F < min_F) {
                                min_F = F;
                                best_result = {home.first, threat.first, S, D, A, dist_SD, dist_SA, dist_DA, F};
                            }
                        }
                    }
                }

                #pragma omp critical
                {
                    std::cout << "   Home: " << home.first << ", Threat: " << threat.first << ", F_min: " << min_F << ", scale: " << scale << ", count: " << local_count << std::endl;
                }

                scale /= 2;
                if (scale < 0.001 || min_F < 10.0) break;
            }

            #pragma omp critical
            {
                std::cout << "Storing local results:: Home country: " << home.first << ", Threat country: " << threat.first << ", F_min: " << min_F << ", scale: " << scale << std::endl;
            }
            local_results.push_back(best_result);
        }

        #pragma omp critical
        {
            results.insert(results.end(), local_results.begin(), local_results.end());
            std::cout << "Processed Home country: " << home.first << std::endl;
        }
    }

    std::ofstream csv("/u/satadals/local/geolocation_based_analysis/data/country_optimal_geodesic.csv");
    csv << "HomeCountry,ThreatCountry,"
        << "S_lat,S_lon,D_lat,D_lon,A_lat,A_lon,"
        << "dist_SD_km,dist_SA_km,dist_DA_km,F_min_km\n";

    for (const auto& res : results) {
        csv << std::fixed << std::setprecision(1)
            << res.homeCountry << ',' << res.threatCountry << ','
            << res.optimal_S.getY() << ',' << res.optimal_S.getX() << ','
            << res.optimal_D.getY() << ',' << res.optimal_D.getX() << ','
            << res.optimal_A.getY() << ',' << res.optimal_A.getX() << ','
            << res.dist_SD << ',' << res.dist_SA << ','
            << res.dist_DA << ',' << res.F_value << '\n';
    }

    for (auto& c : countries) OGRGeometryFactory::destroyGeometry(c.second);
    GDALClose(dataset);
    csv.close();
    std::cout << "Output saved to country_optimal_geodesic.csv\n";
    return 0;
}
