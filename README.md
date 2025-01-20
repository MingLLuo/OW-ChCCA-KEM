A repository for One-Way Checkable CCA(Chosen-Cipherteext Attack) KEM, implemented in Golang.

Paper: [[PWZ2023]Lattice-based Authenticated Key Exchange with Tight Security](https://eprint.iacr.org/2023/823)

For the first time, we will use some package in [Cloudflare/circl](https://github.com/cloudflare/circl) to implement the KEM.

Following the analysis in the paper,the parameters have to satisfy the following conditions.

- The scheme is paramterized by **matrix dimensions** n, m, k $\in \mathbb{N}$, a **modulus** $q \in \mathbb{N}$, **security parameter** $\lambda \in \mathbb{N}$ and (Gaussian) widths $\alpha, \alpha', \gamma, \eta \in \mathbb{R}$.
- $q$ is prime, $m \geq 2n \log q$, $\alpha \geq \omega(\sqrt{\log m})$
- $\alpha,\alpha' \geq \omega(\sqrt{\log m})$
- $n\log(2\eta + 1) - (k + 3\lambda) \log q \geq \lambda \log q + \Omega(n)$
- $\alpha' \geq \beta\eta n mq, \beta q = n$
- For correctness, $4\alpha' \alpha m < q$

Given $\lambda$, we could conservatively use the following parameter setting.
- $n = 70\lambda, n^6  < q \leq n^7, \eta = \gamma = \alpha = \sqrt n$
- $k = \lambda, m = 2n\log q,a' = n^{2.5}m$

We will change them to adapt the real world circumstances.
