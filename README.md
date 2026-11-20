# Threat Hunting Demo - WitFoo Precinct6 Dataset (TK121 UTS)

Demo notebook untuk UTS Threat Hunting & Cyber Threat Intelligence (TK121),
Program Studi S1 Teknik Komputer, Universitas Amikom Yogyakarta.

Dataset: [`witfoo/precinct6-cybersecurity`](https://huggingface.co/datasets/witfoo/precinct6-cybersecurity)
versi 2.1.0 - 2.011.674 baris sinyal SOC dari 4 organisasi, Apache-2.0.

## Hipotesis yang diuji

**H2 - network scanning.** Ada host di ORG-0004 yang memindai port (T1046) atau
mencoba koneksi berulang ke banyak port/host. Diuji dengan metrik *fan-out*
(jumlah port/host unik per jendela waktu), bukan volume flow.

**H3 - EDR tampering.** Ada endpoint di ORG-0004 yang mengalami upaya mematikan
sensor EDR (T1562.001) atau menghapus shadow copy (T1490). Diuji dengan
menormalkan JSON Crowdstrike Falcon lalu mendeduplikasi behavior.

## Cara menjalankan

Buka notebook di Google Colab, lalu Runtime > Run all:

```
https://colab.research.google.com/github/Whit3knight/Threat-Hunting/blob/main/uts_threat_hunting_demo.ipynb
```

Cell pertama meng-install `duckdb` + `huggingface_hub` dan mengunduh empat file
parquet (161 MB) langsung dari Hugging Face. Sesudah itu seluruh notebook selesai
di bawah satu menit.

Menjalankan lokal:

```bash
uv run --with duckdb --with pandas --with matplotlib --with huggingface_hub \
  jupyter notebook uts_threat_hunting_demo.ipynb
```

## Alur demo

1. Unduh data + verifikasi jumlah baris (2.011.674) dan distribusi label.
2. Validasi integritas: 3.287 dari 19.219 baris VPC flow arahnya terbalik
   antara kolom `src_ip`/`dst_ip` dan payload pesan, sehingga semua agregasi
   memakai payload (`str_split(message_sanitized,' ')`).
3. H2 query 1: fan-out port per sumber, jendela 5 menit (temuan 3 kejadian).
4. H2 query 2: fan-out sumber per tujuan, jendela 10 menit (temuan 4 kejadian).
5. H2 query 3: percobaan berulang ke satu port dengan port sumber acak
   (temuan 3 pasangan host, semuanya ke tcp/135).
6. Kalibrasi ambang dari distribusi: 94,4% jendela hanya menyentuh 1 port.
7. H3 query: parse JSON Crowdstrike, unnest `behaviors[]`, dedupe
   (device_id + behavior_id + timestamp + cmdline): 58 artifact -> 76 behavior
   -> 7 perilaku unik pada 2 device.
8. Penyusunan evidence timeline gabungan (waktu kejadian dari payload, bukan
   waktu ingest).
9. Dua chart: volume flow per jam dan fan-out port per sumber.
10. Korelasi ke provenance graph + ekspor CSV.

## Hasil ringkas

| Uji | Angka |
|---|---|
| Baris sinyal | 2.011.674 |
| Label | benign 1.897.153 / suspicious 106.793 / malicious 7.728 |
| VPC flow ORG-0004 | 19.219 baris, semuanya REJECT |
| Arah flow terbalik dari payload | 3.287 baris (17,1%) |
| Kampanye scan 26 Jul 2024 11:19-11:24 UTC | 34 sumber -> 10.189.183.176, 43 port, 2.975 flow |
| Kampanye scan 29 Jul 2024 20:35-20:40 UTC | 49 sumber -> 10.98.236.105, 102 port, 9.920 flow |
| Sumber tersibuk | 100.64.27.187, 5.218 flow, 55 port, 5 menit |
| Percobaan RPC berulang | 10.73.148.8 -> 10.19.72.193:135, 1.689 percobaan, 5,5 hari |
| Artifact EDR | 58 (38 suspicious, 20 malicious) |
| Perilaku EDR unik | 7, pada 2 device (3 binary, 2 akun) |
| Percobaan tampering diblokir sensor | 5 dari 5 |
| Insiden Precinct yang menggabungkan EDR + flow | 0 (celah korelasi) |

Kesimpulan: perilaku terbukti, kompromi tidak. Semua flow di dataset berstatus
REJECT, dan tidak ada bukti aksi lanjutan pada endpoint yang ditamper.

## Isi repository

```
uts_threat_hunting_demo.ipynb   notebook demo (Colab-ready)
data/                           CSV hasil eksekusi notebook
cek_ulang_angka.py              verifikasi 18 angka utama langsung dari parquet
```

`cek_ulang_angka.py` menjalankan ulang setiap angka yang dikutip di laporan dan
mencetak PASS/FAIL per pemeriksaan:

```bash
uv run --with duckdb python cek_ulang_angka.py
```

## Catatan batasan

- Label dataset berasal dari korelasi otomatis WitFoo Precinct, bukan verdict
  analis; seluruh baris `malicious` ber-`mo_name` "Data Theft".
- Satu kampanye bisa terpecah menjadi label `malicious` dan `suspicious` pada
  baris yang berbeda.
- Tidak ada baris ACCEPT pada stream flow, sehingga keberhasilan koneksi tidak
  dapat diukur dari dataset ini.
- Seluruh IP, host, akun, dan organisasi sudah di-token oleh penerbit dataset.
