import argparse
from termcolor import colored
# Dictionary chứa mô tả các đặc trưng trong bộ dữ liệu dataset_phishing.csv
# Các đặc trưng được nhóm thành: URL-based, Content-based, Third-party-based, và Status
# Mỗi đặc trưng có mô tả ngắn gọn và ví dụ (nếu có) để dễ hiểu

phishing_features_dict = {
    # URL-based Features (58 đặc trưng)
    # Các đặc trưng này được trích xuất từ cấu trúc của URL
    "url": """
        URL đầy đủ của trang web.
        Đây là đầu vào chính để phân tích các đặc trưng khác.
        Ví dụ: http://www.crestonwood.com/router.php
    """,
    "length_url": """
        Độ dài của toàn bộ URL (số ký tự).
        URL dài bất thường có thể là dấu hiệu của phishing.
        Ví dụ: http://www.crestonwood.com/router.php có độ dài 37.
    """,
    "length_hostname": """
        Độ dài của hostname (phần domain chính).
        Ví dụ: www.crestonwood.com có độ dài 19.
    """,
    "ip": """
        Hostname có chứa địa chỉ IP không.
        Giá trị: 1 (Có), 0 (Không).
        Ví dụ: http://174.139.46.123 có ip=1.
    """,
    "nb_dots": """
        Số lượng dấu chấm '.' trong URL.
        Ví dụ: http://www.crestonwood.com/router.php có 3 dấu chấm.
    """,
    "nb_hyphens": """
        Số lượng dấu gạch ngang '-' trong URL.
        Ví dụ: https://www.merriam-webster.com có 1 gạch ngang.
    """,
    "nb_at": """
        Số lượng ký tự '@' trong URL.
        Ví dụ: http://www.budgetbots.com/server.php/Server%20update/index.php?email=USER@DOMAIN.com có 1 @.
    """,
    "nb_qm": """
        Số lượng dấu hỏi '?' trong URL.
        Ví dụ: https://onedrive.live.com/?authkey=... có 1 dấu hỏi.
    """,
    "nb_and": """
        Số lượng ký tự '&' trong URL.
        Ví dụ: https://onedrive.live.com/?authkey=...&cid=... có 5 &.
    """,
    "nb_or": """
        Số lượng ký tự '|' trong URL.
        Thường bằng 0 vì hiếm gặp.
    """,
    "nb_eq": """
        Số lượng ký tự '=' trong URL.
        Ví dụ: https://onedrive.live.com/?authkey=...&cid=... có 9 =.
    """,
    "nb_underscore": """
        Số lượng ký tự '_' trong URL.
        Ví dụ: https://en.wikipedia.org/wiki/Firewall_(computing) có 1 _.
    """,
    "nb_tilde": """
        Số lượng ký tự '~' trong URL.
        Thường bằng 0 vì hiếm gặp.
    """,
    "nb_percent": """
        Số lượng ký tự '%' trong URL.
        Ví dụ: https://onedrive.live.com/?authkey=%21AG7v3K%5Fv%5Fvmx0wU... có 4 %.
    """,
    "nb_slash": """
        Số lượng dấu gạch chéo '/' trong URL.
        Ví dụ: http://www.iracing.com/tracks/gateway-motorsports-park/ có 5 /.
    """,
    "nb_star": """
        Số lượng ký tự '*' trong URL.
        Thường bằng 0 vì hiếm gặp.
    """,
    "nb_colon": """
        Số lượng dấu hai chấm ':' trong URL.
        Ví dụ: http://www.crestonwood.com/router.php có 1 :.
    """,
    "nb_comma": """
        Số lượng dấu phẩy ',' trong URL.
        Ví dụ: http://www.inbioma.pe/rechnung-376440790464490488... có 2 ,.
    """,
    "nb_semicolumn": """
        Số lượng dấu chấm phẩy ';' trong URL.
        Thường bằng 0 vì hiếm gặp.
    """,
    "nb_dollar": """
        Số lượng ký tự '$' trong URL.
        Ví dụ: http://www.budgetbots.com/server.php/Server%20update/index.php?email=USER@DOMAIN.com có 1 $.
    """,
    "nb_space": """
        Số lượng ký tự khoảng trắng trong URL.
        Thường bằng 0 vì hiếm gặp.
    """,
    "nb_www": """
        Sự hiện diện của 'www' trong URL.
        Giá trị: 1 (Có), 0 (Không).
        Ví dụ: http://www.crestonwood.com/router.php có nb_www=1.
    """,
    "nb_com": """
        Sự hiện diện của '.com' trong URL.
        Giá trị: 1 (Có), 0 (Không).
        Ví dụ: http://www.crestonwood.com/router.php có nb_com=0.
    """,
    "nb_dslash": """
        Số lượng dấu gạch chéo kép '//' trong URL.
        Ví dụ: http://www.crestonwood.com/router.php có 1 //.
    """,
    "http_in_path": """
        Sự hiện diện của 'http' trong path.
        Giá trị: 1 (Có), 0 (Không).
        Ví dụ: http://174.139.46.123/ap/signin?openid.ns=http%3A... có http_in_path=4.
    """,
    "https_token": """
        Giao thức là HTTPS không.
        Giá trị: 0 (HTTPS), 1 (Không).
        Ví dụ: https://www.crestonwood.com/router.php có https_token=0.
    """,
    "ratio_digits_url": """
        Tỷ lệ ký tự số trong URL (số ký tự số / độ dài URL).
        Ví dụ: http://shadetreetechnology.com/V4/validation/a111aedc8ae390eabcfa130e041a10a4 có ratio_digits_url=0.220779221.
    """,
    "ratio_digits_host": """
        Tỷ lệ ký tự số trong hostname.
        Ví dụ: http://174.139.46.123 có ratio_digits_host=0.785714286.
    """,
    "punycode": """
        URL sử dụng mã hóa Punycode.
        Giá trị: 1 (Có), 0 (Không).
    """,
    "port": """
        URL có chỉ định cổng không.
        Giá trị: 1 (Có), 0 (Không).
    """,
    "tld_in_path": """
        TLD xuất hiện trong path.
        Giá trị: 1 (Có), 0 (Không).
        Ví dụ: http://paypal.com.0.security-confirmation...as2.2u.se/ có tld_in_path=1.
    """,
    "tld_in_subdomain": """
        TLD xuất hiện trong subdomain.
        Giá trị: 1 (Có), 0 (Không).
        Ví dụ: https://support-appleld.com.secureupdate.duilawyeryork.com/... có tld_in_subdomain=1.
    """,
    "abnormal_subdomain": """
        Subdomain có bất thường không.
        Giá trị: 1 (Có), 0 (Không).
        Ví dụ: https://support-appleld.com.secureupdate.duilawyeryork.com/... có abnormal_subdomain=1.
    """,
    "nb_subdomains": """
        Số lượng subdomain trong URL.
        Ví dụ: http://www.crestonwood.com/router.php có nb_subdomains=3.
    """,
    "prefix_suffix": """
        Domain có dấu gạch ngang '-' không.
        Giá trị: 1 (Có), 0 (Không).
        Ví dụ: https://www-cwbank.com/en/business có prefix_suffix=1.
    """,
    "random_domain": """
        Domain là chuỗi ngẫu nhiên.
        Giá trị: 1 (Có), 0 (Không).
        Ví dụ: http://xh167894743.el.r.appspot.com/ có random_domain=1.
    """,
    "shortening_service": """
        URL sử dụng dịch vụ rút gọn.
        Giá trị: 1 (Có), 0 (Không).
        Ví dụ: https://rebrand.ly/zitln6v có shortening_service=1.
    """,
    "path_extension": """
        Path có chứa phần mở rộng tệp (.php, .html).
        Giá trị: 1 (Có), 0 (Không).
        Ví dụ: http://www.crestonwood.com/router.php có path_extension=1.
    """,
    "nb_redirection": """
        Số lượng chuyển hướng khi truy cập trang.
        Ví dụ: http://www.crestonwood.com/router.php có nb_redirection=0.
    """,
    "nb_external_redirection": """
        Số lượng chuyển hướng đến domain bên ngoài.
        Ví dụ: http://www.crestonwood.com/router.php có nb_external_redirection=0. 
    """,
    "length_words_raw": """
        Số lượng từ trong URL (sau khi tách).
        Ví dụ: http://www.crestonwood.com/router.php có length_words_raw=4.
    """,
    "char_repeat": """
        Số lượng ký tự lặp lại liên tiếp trong URL.
        Ví dụ: http://www.crestonwood.com/router.php có char_repeat=4.
    """,
    "shortest_words_raw": """
        Độ dài của từ ngắn nhất trong URL.
        Ví dụ: http://www.crestonwood.com/router.php có shortest_words_raw=3.
    """,
    "shortest_word_host": """
        Độ dài của từ ngắn nhất trong hostname.
        Ví dụ: http://www.crestonwood.com/router.php có shortest_word_host=3.
    """,
    "shortest_word_path": """
        Độ dài của từ ngắn nhất trong path.
        Ví dụ: http://www.crestonwood.com/router.php có shortest_word_path=3.
    """,
    "longest_words_raw": """
        Độ dài của từ dài nhất trong URL.
        Ví dụ: http://www.crestonwood.com/router.php có longest_words_raw=11.
    """,
    "longest_word_host": """
        Độ dài của từ dài nhất trong hostname.
        Ví dụ: http://www.crestonwood.com/router.php có longest_word_host=11.
    """,
    "longest_word_path": """
        Độ dài của từ dài nhất trong path.
        Ví dụ: http://www.crestonwood.com/router.php có longest_word_path=6.
    """,
    "avg_words_raw": """
        Độ dài trung bình của các từ trong URL.
        Ví dụ: http://www.crestonwood.com/router.php có avg_words_raw=5.75.
    """,
    "avg_word_host": """
        Độ dài trung bình của các từ trong hostname.
        Ví dụ: http://www.crestonwood.com/router.php có avg_word_host=7.0.
    """,
    "avg_word_path": """
        Độ dài trung bình của các từ trong path.
        Ví dụ: http://www.crestonwood.com/router.php có avg_word_path=4.5.
    """,
    "phish_hints": """
        Số lượng từ khóa liên quan đến phishing (login, signin, v.v.).
        Ví dụ: http://eden.it-guys.net.nz/wp-content/languages/plugins/ugh/Entrar/Login/... có phish_hints=6.
    """,
    "domain_in_brand": """
        Domain chứa tên thương hiệu nổi tiếng.
        Giá trị: 1 (Có), 0 (Không).
        Ví dụ: http://appleid.apple.com-app.es/ có domain_in_brand=0.
    """,
    "brand_in_subdomain": """
        Subdomain chứa tên thương hiệu.
        Giá trị: 1 (Có), 0 (Không).
        Ví dụ: https://support-appleld.com.secureupdate.duilawyeryork.com/... có brand_in_subdomain=0.
    """,
    "brand_in_path": """
        Path chứa tên thương hiệu.
        Giá trị: 1 (Có), 0 (Không).
        Ví dụ: http://swallowthisbitchpics.com/jpg/www.global.visa.com/... có brand_in_path=1.
    """,
    "suspecious_tld": """
        TLD nằm trong danh sách đáng ngờ.
        Giá trị: 1 (Có), 0 (Không).
        Ví dụ: http://www.inbioma.pe/... có suspecious_tld=1.
    """,
    "statistical_report": """
        Domain có trong báo cáo lừa đảo.
        Giá trị: 1 (Có), 0 (Không).
        Ví dụ: http://paypal.com.0.security-confirmation...as2.2u.se/ có statistical_report=2.
    """,

    # Content-based Features (24 đặc trưng)
    # Các đặc trưng này được trích xuất từ nội dung trang web
    "nb_hyperlinks": """
        Tổng số liên kết (hyperlinks) trên trang web.
        Ví dụ: http://www.crestonwood.com/router.php có nb_hyperlinks=17.
    """,
    "ratio_intHyperlinks": """
        Tỷ lệ liên kết nội bộ so với tổng số liên kết.
        Ví dụ: http://www.crestonwood.com/router.php có ratio_intHyperlinks=0.529411765.
    """,
    "ratio_extHyperlinks": """
        Tỷ lệ liên kết bên ngoài so với tổng số liên kết.
        Ví dụ: http://www.crestonwood.com/router.php có ratio_extHyperlinks=0.470588235.
    """,
    "ratio_nullHyperlinks": """
        Tỷ lệ liên kết rỗng (không dẫn đến đâu).
        Ví dụ: Thường bằng 0 vì không có liên kết rỗng trong các mẫu dữ liệu.
    """,
    "nb_extCSS": """
        Số lượng tệp CSS bên ngoài được liên kết.
        Ví dụ: http://www.mutuo.it có nb_extCSS=10.
    """,
    "ratio_intRedirection": """
        Tỷ lệ liên kết nội bộ gây chuyển hướng.
        Ví dụ: http://www.crestonwood.com/router.php có ratio_intRedirection=0.875.
    """,
    "ratio_extRedirection": """
        Tỷ lệ liên kết bên ngoài gây chuyển hướng.
        Ví dụ: http://www.crestonwood.com/router.php có ratio_extRedirection=0.5.
    """,
    "ratio_intErrors": """
        Tỷ lệ liên kết nội bộ dẫn đến lỗi (như 404).
        Ví dụ: http://www.crestonwood.com/router.php có ratio_intErrors=0.
    """,
    "ratio_extErrors": """
        Tỷ lệ liên kết bên ngoài dẫn đến lỗi.
        Ví dụ: http://www.crestonwood.com/router.php có ratio_extErrors=0.5.
    """,
    "login_form": """
        Trang có chứa biểu mẫu đăng nhập.
        Giá trị: 1 (Có), 0 (Không).
        Ví dụ: http://www.iracing.com/tracks/gateway-motorsports-park/ có login_form=1.
    """,
    "external_favicon": """
        Favicon được tải từ domain bên ngoài.
        Giá trị: 1 (Có), 0 (Không).
        Ví dụ: http://www.mutuo.it có external_favicon=1.
    """,
    "links_in_tags": """
        Tỷ lệ liên kết trong các thẻ HTML (như <a>).
        Ví dụ: http://www.crestonwood.com/router.php có links_in_tags=80.0.
    """,
    "submit_email": """
        Biểu mẫu gửi dữ liệu đến email.
        Giá trị: 1 (Có), 0 (Không).
        Ví dụ: http://www.dmega.co.kr/dmega/data/qna/sec/page.php?email=... có submit_email=1.
    """,
    "ratio_intMedia": """
        Tỷ lệ tài nguyên media nội bộ (hình ảnh, video).
        Ví dụ: http://www.crestonwood.com/router.php có ratio_intMedia=100.0.
    """,
    "ratio_extMedia": """
        Tỷ lệ tài nguyên media bên ngoài.
        Ví dụ: http://www.iracing.com/tracks/gateway-motorsports-park/ có ratio_extMedia=100.0.
    """,
    "sfh": """
        Biểu mẫu gửi dữ liệu đến server khác hostname.
        Giá trị: 1 (Có), 0 (Không).
        Ví dụ: Thường bằng 0 trong các mẫu dữ liệu.
    """,
    "iframe": """
        Trang có sử dụng iframe.
        Giá trị: 1 (Có), 0 (Không).
        Ví dụ: Thường bằng 0 trong các mẫu dữ liệu.
    """,
    "popup_window": """
        Trang có cửa sổ bật lên (popup).
        Giá trị: 1 (Có), 0 (Không).
        Ví dụ: Thường bằng 0 trong các mẫu dữ liệu.
    """,
    "safe_anchor": """
        Tỷ lệ liên kết anchor an toàn (không dẫn đến nội dung độc hại).
        Ví dụ: http://www.crestonwood.com/router.php có safe_anchor=0.0.
    """,
    "onmouseover": """
        Trang có sử dụng sự kiện onmouseover.
        Giá trị: 1 (Có), 0 (Không).
        Ví dụ: Thường bằng 0 trong các mẫu dữ liệu.
    """,
    "right_clic": """
        Trang vô hiệu hóa nhấp chuột phải.
        Giá trị: 1 (Có), 0 (Không).
        Ví dụ: http://www.ktplasmachinery.com/cs/ có right_clic=1.
    """,
    "empty_title": """
        Tiêu đề trang (title) rỗng.
        Giá trị: 1 (Có), 0 (Không).
        Ví dụ: http://www.ktplasmachinery.com/cs/ có empty_title=1.
    """,
    "domain_in_title": """
        Domain không xuất hiện trong tiêu đề trang.
        Giá trị: 1 (Không), 0 (Có).
        Ví dụ: http://www.crestonwood.com/router.php có domain_in_title=1.
    """,
    "domain_with_copyright": """
        Domain xuất hiện trong nội dung bản quyền.
        Giá trị: 1 (Có), 0 (Không).
        Ví dụ: http://www.crestonwood.com/router.php có domain_with_copyright=1.
    """,

    # Third-party-based Features (6 đặc trưng)
    # Các đặc trưng này dựa trên thông tin từ các dịch vụ bên thứ ba
    "whois_registered_domain": """
        Domain được đăng ký hợp lệ.
        Giá trị: 1 (Không), 0 (Có).
        Ví dụ: http://www.crestonwood.com/router.php có whois_registered_domain=0.
    """,
    "domain_registration_length": """
        Thời gian domain được đăng ký (ngày).
        Ví dụ: http://www.crestonwood.com/router.php có domain_registration_length=45.
    """,
    "domain_age": """
        Tuổi của domain (ngày).
        Ví dụ: http://www.crestonwood.com/router.php có domain_age=-1 (không xác định).
    """,
    "web_traffic": """
        Lưu lượng truy cập web của URL.
        Thường trả về 0 nếu thiếu API.
        Ví dụ: http://www.iracing.com/tracks/gateway-motorsports-park/ có web_traffic=8725.
    """,
    "dns_record": """
        Domain có bản ghi DNS.
        Giá trị: 1 (Không), 0 (Có).
        Ví dụ: http://www.crestonwood.com/router.php có dns_record=1.
    """,
    "google_index": """
        URL được Google lập chỉ mục.
        Giá trị: 1 (Không), 0 (Có).
        Ví dụ: http://www.crestonwood.com/router.php có google_index=1.
    """,
    "page_rank": """
        Xếp hạng trang (PageRank) của domain.
        Ví dụ: http://www.crestonwood.com/router.php có page_rank=4.
    """,

    # Status (1 đặc trưng)
    # Nhãn phân loại của URL
    "status": """
        Nhãn phân loại của URL.
        Giá trị: legitimate (hợp pháp) hoặc phishing (lừa đảo).
        Ví dụ: http://www.crestonwood.com/router.php có status=legitimate.
    """
}

def print_feature(feature_key):
    """In mô tả của một đặc trưng với định dạng đẹp."""
    if feature_key not in phishing_features_dict:
        print(colored(f"✗ Đặc trưng '{feature_key}' không tồn tại trong từ điển.", "red"))
        return

    # Tạo tiêu đề và đường viền
    print(colored("═" * 60, "cyan"))
    print(colored(f"Đặc trưng: {feature_key}", "yellow", attrs=["bold"]))
    print(colored("Giải thích:", "green"))
    # In mô tả, loại bỏ khoảng trắng thừa và căn lề
    description = "\n".join(line.strip() for line in phishing_features_dict[feature_key].strip().split("\n"))
    print(description)
    print(colored("═" * 60, "cyan"))
    print()  # Thêm dòng trống để phân cách

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Tra cứu mô tả các đặc trưng trong bộ dữ liệu phishing")
    parser.add_argument('--features', nargs='+', help='Danh sách các đặc trưng cần tra cứu (ví dụ: length_url nb_dots)')
    args = parser.parse_args()

    # Kiểm tra xem có đặc trưng nào được cung cấp không
    if not args.features:
        print(colored("✗ Vui lòng cung cấp ít nhất một đặc trưng để tra cứu.", "red"))
        print("Ví dụ: python feature_dictionary.py --features length_url nb_dots")
    else:
        for key in args.features:
            print_feature(key)
