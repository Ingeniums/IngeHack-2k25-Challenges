#include <cmath>
#include <complex>
#include <cstdint>
#include <cstdio>
#include <fcntl.h>
#include <fstream>
#include <iostream>
#include <unistd.h>
#include <vector>

const char *ascii_art = R"(
,----,------------------------------,------.
| ## |                              |    - |
| ## |                              |    - |
|    |------------------------------|    - |
|    ||............................||      |   PRINTER
|    ||,-                        -.||      |
|    ||___                      ___||    ##|
|    ||---`--------------------'---||      |
`--mb'|_|______________________==__|`------'

PRESS [ENTER] TO START
)";

const double PI = acos(-1);

std::vector<std::complex<double>> readfile(const std::string &filename) {
  std::ifstream file(filename, std::ios::binary);
  file.seekg(0, std::ios::end);
  size_t fileSize = file.tellg();
  file.seekg(0, std::ios::beg);

  std::vector<double> dbls(fileSize / sizeof(double));
  file.read(reinterpret_cast<char *>(dbls.data()), fileSize);

  std::vector<std::complex<double>> complexVector;
  for (uint64_t i = 0; i < dbls.size(); i += 2) {
    complexVector.emplace_back(std::complex<double>(dbls[i], dbls[i + 1]));
  }

  return complexVector;
}

int main() {
  std::cout << ascii_art << std::endl;
  getchar();

  auto data = std::move(readfile("./enc"));

  size_t N = data.size();
  std::vector<std::complex<double>> x(N);

  for (size_t n = 0; n < N; ++n) {
    std::complex<double> sum(0.0, 0.0);
    for (size_t k = 0; k < N; ++k) {
      double angle = 2 * M_PI * k * n / N;
      std::complex<double> expTerm(std::cos(angle), std::sin(angle));
      sum += data[k] * expTerm;
    }
    x[n] = sum / static_cast<double>(N);
    std::cout << lround(x[n].real()) << std::endl;
  }

  data = x;

  return 0;
}
