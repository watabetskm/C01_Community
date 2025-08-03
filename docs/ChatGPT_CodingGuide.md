 # 📘 第00章：入力値検査とデータの無害化（IDS）
## 概要
外部から受け取るデータはすべて「信頼できないもの」として扱い、入力値検査（バリデーション）や無害化（サニタイズ）を徹底することで、SQLインジェクションやクロスサイトスクリプティング、ZIP スリップなどの脆弱性を防ぎます。(JP-CERT)

## IDS00-J: 信頼境界を越えて渡される信頼できないデータは無害化する
•	解説
ユーザ入力や外部システムから渡されるデータを、そのまま処理に利用すると、SQLインジェクションやコマンドインジェクションなどに悪用される恐れがあります。特にデータベースやシェルコマンドに渡す前には、必ず無害化（エスケープ処理やパラメタバインディング）を行うことが必須です。

### •	❌ 悪い例（脆弱・SQLインジェクション）
	// ユーザ入力を直接 SQL 文に組み込んでいるため、' OR '1'='1 のような入力で全件取得される恐れがある
	public List<User> findUsers(String username) throws SQLException {
	    Statement stmt = connection.createStatement();
	    String sql = "SELECT * FROM users WHERE username = '" + username + "'";
	    ResultSet rs = stmt.executeQuery(sql);
	    // 結果を加工して return ・・・
	}

### •	✅ 良い例（安全・PreparedStatement）
	public List<User> findUsers(String username) throws SQLException {
	    String sql = "SELECT * FROM users WHERE username = ?";
	    try (PreparedStatement pstmt = connection.prepareStatement(sql)) {
	        pstmt.setString(1, username);
	        try (ResultSet rs = pstmt.executeQuery()) {
	            // 結果を加工して return ・・・
	        }
	    }
	}
*	PreparedStatement を使うことで、内部的にパラメータを自動でエスケープするため、SQLインジェクションを防ぎます。
 
## IDS01-J: 文字列は検査する前に標準化（正規化）する
•	解説
Unicode などでは、同じ見た目でも異なるコードポイント列（ノーマライズ前）として表現されることがあります。たとえば é は \u00E9 のほかに e + \u0301 としても表されるため、そのままバリデーションすると想定外の振る舞いを招きます。検証前に一度正規化（NFC など）を行い、文字列を統一した上でチェックすることが推奨されます。

### •	❌ 悪い例
	// 入力された文字列をそのまま長さチェック
	public boolean isValidUsername(String input) {
	    return input.length() >= 3 && input.length() <= 20;
	}

### •	✅ 良い例
	import java.text.Normalizer;
	import java.text.Normalizer.Form;
	
	public boolean isValidUsername(String input) {
	    // NFC で正規化
	    String normalized = Normalizer.normalize(input, Form.NFC);
	    if (normalized.length() < 3 || normalized.length() > 20) {
	        return false;
	    }
	    // アルファベット・数字・一部記号のみ許可（例）
	    return normalized.matches("^[a-zA-Z0-9_\\-]+$");
	}
*	Normalizer.normalize(..., Form.NFC) で正規化し、同一表現を統一してから長さやパターンを検査します。
 
## IDS02-J: パス名は検証する前に正規化する
•	解説
ファイルパスやディレクトリパスにおいて、../ を多用することで意図しないファイルにアクセスされる「パストラバーサル攻撃」が発生します。攻撃を防ぐには、ファイル操作前にパスを Path.normalize() などで正規化し、その結果が想定範囲内（例：特定ディレクトリ配下）であるかを必ずチェックします。

### •	❌ 悪い例
	// 外部入力をそのままファイル名として使用し、任意のファイルにアクセスされる恐れがある
	public String readFile(String filename) throws IOException {
	    File file = new File("/data/upload/" + filename);
	    try (BufferedReader br = new BufferedReader(new FileReader(file))) {
	        return br.readLine();
	    }
	}

### •	✅ 良い例
	import java.nio.file.Files;
	import java.nio.file.Path;
	import java.nio.file.Paths;
	
	public String readFile(String filename) throws IOException {
	    Path baseDir = Paths.get("/data/upload").toRealPath().normalize();
	    Path target = baseDir.resolve(filename).normalize();
	    // baseDir 配下かどうかをチェック
	    if (!target.startsWith(baseDir)) {
	        throw new SecurityException("不正なパス指定: " + filename);
	    }
	    return Files.readString(target);
	}

*	Paths.get(...).toRealPath().normalize() でベースディレクトリを正規化し、resolve(...).normalize() で結合後に再度正規化。
*	startsWith(baseDir) によって、脱出（../）が防止できます。


## IDS03-J: ユーザ入力を無害化せずにログに保存しない
•	解説
ログファイルにユーザ入力をそのまま出力すると、後からログ閲覧を行う運用者や管理者がマルウェア（攻撃コード含む）を踏むリスクがあります。特に可視化ツールやログ解析ツールが HTML などをレンダリングした際に「クロスサイトスクリプティング」が成立する可能性もあるため、ログ出力前に厳格に無害化（＝エスケープ）してから出力します。

### •	❌ 悪い例
	// 例: ユーザ名に <script> を含められた場合、
	// Web ベースのログビューアで実行される恐れがある
	public void logLogin(String username) {
	    logger.info("User logged in: " + username);
	}

### •	✅ 良い例
	import org.apache.commons.text.StringEscapeUtils;
	
	public void logLogin(String username) {
	    // HTML/Java/ログ専用のエスケープを行う
	    String safeUser = StringEscapeUtils.escapeJava(username);
	    logger.info("User logged in: " + safeUser);
	}
*	Apache Commons Text の StringEscapeUtils.escapeJava(...) などを活用し、制御文字や特殊文字を安全にエスケープすることで、ログファイル上の意図しないコード実行を防ぎます。


## IDS04-J: ZipInputStream に渡すファイルサイズは制限し、Zipスリップ攻撃を防ぐ
•	解説
ZIP ファイルを展開する際、アーカイブ内のエントリ名に ../../etc/passwd のように記載されると、サーバ側の任意の場所を書き換えられる「ZIPスリップ」攻撃が発生します。これを防ぐには、解凍前にエントリ名を正規化して展開先ディレクトリから逸脱しないかチェックするとともに、全体のファイルサイズに上限を設けます。

### •	❌ 悪い例
	public void unzip(File zipFile, File destDir) throws IOException {
	    try (ZipInputStream zis = new ZipInputStream(new FileInputStream(zipFile))) {
	        ZipEntry entry;
	        while ((entry = zis.getNextEntry()) != null) {
	            File outFile = new File(destDir, entry.getName());
	            try (FileOutputStream fos = new FileOutputStream(outFile)) {
	                byte[] buffer = new byte[4096];
	                int len;
	                while ((len = zis.read(buffer)) > 0) {
	                    fos.write(buffer, 0, len);
	                }
	            }
	        }
	    }
	}

### •	✅ 良い例
	import java.nio.file.Files;
	import java.nio.file.Path;
	import java.nio.file.Paths;
	import java.nio.file.StandardCopyOption;
	import java.util.zip.ZipEntry;
	import java.util.zip.ZipInputStream;
	
	public void unzip(File zipFile, File destDir) throws IOException {
	    Path destDirPath = destDir.toPath().toRealPath().normalize();
	    try (ZipInputStream zis = new ZipInputStream(new FileInputStream(zipFile))) {
	        ZipEntry entry;
	        long totalUnpackedSize = 0;
	        final long MAX_TOTAL_SIZE = 500L * 1024 * 1024; // 例: 最大 500MB
	
	        while ((entry = zis.getNextEntry()) != null) {
	            // パス正規化してディレクトリ外への脱出を防止
	            Path targetPath = destDirPath.resolve(entry.getName()).normalize();
	            if (!targetPath.startsWith(destDirPath)) {
	                throw new SecurityException("Zipスリップ攻撃を検出: " + entry.getName());
	            }
	
	            // 大きすぎる場合は処理を中断
	            totalUnpackedSize += entry.getSize() > 0 ? entry.getSize() : 0;
	            if (totalUnpackedSize > MAX_TOTAL_SIZE) {
	                throw new IOException("展開サイズが制限を超過しました");
	            }
	
	            // ディレクトリの場合は作成、ファイルなら標準コピー
	            if (entry.isDirectory()) {
	                Files.createDirectories(targetPath);
	            } else {
	                Files.createDirectories(targetPath.getParent());
	                Files.copy(zis, targetPath, StandardCopyOption.REPLACE_EXISTING);
	            }
	        }
	    }
	}

*	.toRealPath().normalize() で実際のパスを確保し、resolve(...).normalize() との比較で脱出を検出。
*	合計展開サイズに制限をかけることで、Zip Bomb 攻撃にも対策。
 
## IDS05-J: コマンドライン引数や Runtime.exec()／ProcessBuilder に渡す信頼できないデータは無害化する
•	解説
コマンドインジェクションを防ぐため、シェルコマンドを直接文字列結合で生成せず、ProcessBuilderや Runtime.exec(String[]) を用いるか、外部プログラムへの引数に渡す前にエスケープを行う必要があります。

### •	❌ 悪い例
	// 入力次第で「; rm -rf /」のようなコマンド実行を許してしまう
	public void listDirectory(String dir) throws IOException {
	    String command = "ls " + dir;
	    Runtime.getRuntime().exec(command);
	}

### •	✅ 良い例
	public void listDirectory(String dir) throws IOException {
	    // 配列形式で渡すことでエスケープが自動化され、シェルインジェクションを防ぐ
	    ProcessBuilder pb = new ProcessBuilder("ls", dir);
	    pb.start();
	}

*	new ProcessBuilder("ls", dir) のように引数を分離すると、シェル展開を経ず引数として直接渡されるため、インジェクションのリスクが大幅に低減します。
※Windows 環境では "cmd.exe", "/c", "dir", dir のように配列形式で指定します。


## IDS06-J: 無害化されていないユーザ入力をフォーマット文字列に含めない
•	解説
String.format() や MessageFormat、printf 系メソッドを使う際、ユーザ入力をそのままフォーマットパラメータとして渡すと、予期しない置換や例外、情報漏えいを引き起こす可能性があります。フォーマット文字列は固定し、ユーザ入力はパラメータとして渡すか、あらかじめエスケープしてください。

### •	❌ 悪い例
	public void logMessage(String userMsg) {
	    // フォーマット文字列自体をユーザ入力から生成しているため、
	    // "%x %x %x" のような入力で混乱を招き、例外が発生する
	    String format = userMsg;
	    System.out.printf(format);
	}

### •	✅ 良い例
	public void logMessage(String userMsg) {
	    // フォーマット文字列は固定し、ユーザ入力は引数として渡す
	    System.out.printf("User says: %s%n", userMsg);
	}

*	フォーマット文字列を固定することで、% 系の特殊文字を悪用されるリスクを抑えられます。


## IDS07-J: XML にデータを埋め込むときは適切にエスケープし、XXE（XML External Entity）を防止する
•	解説
XML をパースするときに外部エンティティを許可していると、攻撃者が悪意ある DTD を挿入し、サーバ上のファイルを読み込ませる XXE 攻撃につながります。また、ユーザ入力をそのまま XML に埋め込むと、XML インジェクションを引き起こす恐れがあります。

### •	❌ 悪い例
	// デフォルト設定のまま XML を読み込むと XXE 攻撃が可能
	DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
	DocumentBuilder builder = factory.newDocumentBuilder();
	Document doc = builder.parse(new File("user_input.xml"));

### •	✅ 良い例
	import javax.xml.parsers.DocumentBuilder;
	import javax.xml.parsers.DocumentBuilderFactory;
	
	public Document parseXml(File xmlFile) throws Exception {
	    DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
	
	    // 外部エンティティおよび DOCTYPE 宣言を無効化して XXE を防止
	    factory.setFeature("http://xml.org/sax/features/external-general-entities", false);
	    factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
	    factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
	    factory.setXIncludeAware(false);
	    factory.setExpandEntityReferences(false);
	
	    DocumentBuilder builder = factory.newDocumentBuilder();
	    return builder.parse(xmlFile);
	}

*	各種 setFeature(...) で外部エンティティや DTD の使用を明示的に禁止し、XXE を防止しています。


# 📗 第01章：宣言と初期化（DCL）
## 概要
クラスや変数の宣言・初期化タイミングに関するルールを定め、静的初期化の循環参照や不適切なデフォルト値などを防ぐことで、実行時の予期せぬ挙動や脆弱性の発生を抑制します。(JP-CERT)

## DCL00-J: クラスの静的初期化子で循環参照を発生させない
•	解説
Java の静的初期化子（static { ... }）や静的フィールド内で相互にインスタンスを生成すると、初期化順序の予測が困難になり、NullPointerException や StackOverflowError の原因となります。初期化の順序を明確にするか、循環参照を断ち切る設計にしましょう。

### •	❌ 悪い例
	public class A {
	    // B のインスタンス生成時に B が A のインスタンスを生成しようとして循環する
	    static B b = new B();
	}
	
	public class B {
	    static A a = new A();
	}

### •	✅ 良い例
	public class A {
	    static B b;
	    static {
	        b = new B(); // A の初期化ブロック内で B を生成
	    }
	}
	
	public class B {
	    static A a;
	    static {
	        a = new A(); // B の初期化ブロック内で A を生成
	    }
	}

* 初期化ブロックを使うことで、サイクルが生じにくい構造に。ただし、依存関係自体を見直し、そもそも相互に初期化しない設計が望ましい。

 
## DCL01-J: final フィールドは常に明示的に初期化する
•	解説
final フィールドをデフォルト値に頼って曖昧に初期化すると、後々のリファクタリング時に意図しない未初期化状態（null や 0）が残るリスクがあります。定数や final フィールドは必ず宣言時、またはコンストラクタ内で明示的に初期化してください。

### •	❌ 悪い例
	public class Config {
	    // IDEによっては初期化が明示されず、後から意図しない変更を許してしまう
	    public final String version;
	    
	    public Config() {
	        // version を設定し忘れるとコンパイルエラーにはなるが、
	        // 後からローカル変数から値を代入する設計は避ける
	    }
	}

### •	✅ 良い例
	public class Config {
	    public final String version;
	
	    public Config(String version) {
	        // コンストラクタ引数で明示的に初期化する
	        this.version = version;
	    }
	}

*	final フィールドは必ず宣言時かコンストラクタ内で一度だけ初期化することで、後から書き換えられることを防ぎます。



## 📙 第02章：式（EXP）
概要
式の評価やメソッド呼び出しに関するルールを定め、戻り値の無視や比較演算の誤り、条件式の不備などを防ぎます。(JP-CERT)

## EXP00-J: メソッドの戻り値を無視しない
•	解説
多くのメソッドは呼び出し結果を戻り値として返しますが、それを無視すると誤った動作や想定外の分岐が起こることがあります。特にコレクション操作や I/O 操作など戻り値によって正常終了・異常終了が判別できるものは、必ず戻り値をチェックしましょう。

### •	❌ 悪い例
	List<String> list = new ArrayList<>();
	// remove メソッドの戻り値を無視している ⇒ 実際には削除されていない可能性がある
	list.remove("target");

### •	✅ 良い例
	List<String> list = new ArrayList<>();
	boolean removed = list.remove("target");
	if (!removed) {
	    System.out.println("要素が削除されませんでした: target");
	}

*	戻り値が false の場合、要素がそもそも存在しなかった可能性があるため適切にハンドリングします。
 

## EXP01-J: ビット演算／数値演算で符号拡張やキャストミスを起こさない
•	解説
Javaでは整数型を扱うとき、byte→int への符号拡張や、ビットシフトの優先順序によって想定しない結果を得る恐れがあります。演算前後で適切にキャストし、ビット演算子の挙動を理解しておくことが重要です。

### •	❌ 悪い例
	byte b = (byte) 0xF0; // -16
	int i = b >> 4;       // 結果は -1（符号ビットが拡張されるため）

### •	✅ 良い例
	byte b = (byte) 0xF0; // -16
	int i = (b & 0xFF) >> 4; // 0xF0 & 0xFF = 240, 240 >> 4 = 15

*	& 0xFF で符号拡張を抑制し、正しくビット右シフトした結果を得ています。


## 📒 第03章：数値型とその操作（NUM）
概要
整数オーバーフローや浮動小数点の精度問題、キャストによる情報損失、数値比較の落とし穴などを防ぐルールを定めています。(JP-CERT)

## NUM00-J: 整数演算でオーバーフローを検出する
•	解説
Javaでは、int や long の加算・乗算でオーバーフローが起きても例外は発生せずただ折り返します。計算結果が予想を超える場合は、Math.addExact() や Math.multiplyExact() を使うか、あらかじめ範囲チェックを行いましょう。

### •	❌ 悪い例
	int a = Integer.MAX_VALUE;
	int b = 1;
	int result = a + b; // 整数オーバーフローし、result は -2147483648 になる

### •	✅ 良い例
	try {
	    int result = Math.addExact(a, b);
	} catch (ArithmeticException e) {
	    // オーバーフロー発生時の処理
	}

*	Math.addExact はオーバーフロー時に ArithmeticException をスローするため、安全に検出できます。


## NUM01-J: 浮動小数点変数をループカウンタに使用しない
•	解説
浮動小数点（float／double）は IEEE 754 準拠で誤差を含むため、ループカウンタに使うと意図しないループ回数や無限ループを招く恐れがあります。ループには必ず整数型（int／long）を使いましょう。

### •	❌ 悪い例
	// 0.1 を足し続けると、誤差により無限ループの可能性がある
	for (double x = 0.0; x != 1.0; x += 0.1) {
	    // do something
	}

### •	✅ 良い例
	for (int i = 0; i < 10; i++) {
	    double x = i * 0.1; // ループカウンタは int
	    // do something
	}


## 📓 第04章：文字と文字列（STR）
概要
文字列操作におけるバッファオーバーフローや不適切な正規表現、文字エンコーディングミスを防ぐルールを定めています。(JP-CERT)

## STR00-J: 文字列連結は StringBuilder を使い、大量連結で性能と脆弱性を防ぐ
•	解説
String の連結（+ 演算子）は内部で毎回新しい String インスタンスを生成し、性能劣化を引き起こす場合があります。また、多数の部分文字列を連結するとヒープメモリを大量消費し、DoS（サービス拒否）につながる可能性があるため、大量の連結には StringBuilder を使いましょう。

### •	❌ 悪い例
	public String joinNames(List<String> names) {
	    String result = "";
	    for (String n : names) {
	        result += n + ",";
	    }
	    return result;
	}

### •	✅ 良い例
	public String joinNames(List<String> names) {
	    StringBuilder sb = new StringBuilder();
	    for (String n : names) {
	        sb.append(n).append(",");
	    }
	    return sb.toString();
	}

*	StringBuilder を使うことで、中間オブジェクトの生成を抑え、メモリ消費と性能劣化を回避します。


## STR01-J: 正規表現を扱う際、ユーザ入力を直接パターンに含めない
•	解説
ユーザ入力をそのまま正規表現に含めると、ReDoS（正規表現による DoS）や不正なパターンによる例外を引き起こす恐れがあります。ユーザから受け取った文字列は、あらかじめ Pattern.quote(...) などでエスケープしてからパターンを生成するか、ホワイトリスト方式で入力文字を絞り込みましょう。

### •	❌ 悪い例
	public boolean matchesPattern(String userPattern, String input) {
	    // userPattern が "(a+)+" のような複雑なパターンだと ReDoS の恐れあり
	    return input.matches(userPattern);
	}
### •	✅ 良い例
	import java.util.regex.Pattern;
	
	public boolean containsLiteral(String literal, String input) {
	    // Pattern.quote で入力をエスケープし、リテラルマッチを行う
	    String safePattern = ".*" + Pattern.quote(literal) + ".*";
	    return input.matches(safePattern);
	}

*	Pattern.quote(...) を使うことで、ユーザ入力中のメタ文字をすべてエスケープし、ReDoS や意図しないマッチングを回避します。
 
## 📔 第05章：オブジェクト指向（OBJ）
概要
継承・ポリモーフィズム・可視性など、オブジェクト指向設計においてセキュリティに影響を与えるポイントを定めています。外部からアクセス可能なメソッドやフィールド、オーバーライドの危険性などを管理し、意図しない挙動や情報漏えいを防ぎます。(JP-CERT)

## OBJ00-J: 継承関係では、オーバーライド可能なメソッドに注意する
•	解説
スーパークラスのコンストラクタ内で this.doSomething() のようにメソッドを呼び出すと、サブクラスでオーバーライドされたメソッドが実行され、初期化前の状態で動作させてしまう恐れがあります（Fragile Base Class 問題）。可能な限り、コンストラクタ内でオーバーライド可能なメソッドを呼び出さないように設計しましょう。

### •	❌ 悪い例
	public class SuperClass {
	    public SuperClass() {
	        // サブクラスでオーバーライドされた doLogic() が呼ばれてしまう
	        doLogic();
	    }
	    public void doLogic() {
	        System.out.println("Super logic");
	    }
	}
	
	public class SubClass extends SuperClass {
	    private String value = "initialized";
	
	    public SubClass() {
	        super();
	    }
	
	    @Override
	    public void doLogic() {
	        // value はコンストラクタ完了前なので null の可能性がある
	        System.out.println("Sub logic: " + value.length());
	    }
	}

### •	✅ 良い例
	public class SuperClass {
	    // コンストラクタ内では final メソッドや private メソッドのみを呼び出す
	    public SuperClass() {
	        initialize();
	    }
	    private void initialize() {
	        System.out.println("Super initialized");
	    }
	
	    public void doLogic() {
	        System.out.println("Super logic");
	    }
	}
	
	public class SubClass extends SuperClass {
	    private String value;
	
	    public SubClass() {
	        // super() 内では doLogic() を呼ばないため安全
	        super();
	        value = "initialized";
	    }
	
	    @Override
	    public void doLogic() {
	        // 初期化後に明示的に呼び出す
	        System.out.println("Sub logic: " + value.length());
	    }
	}

*	コンストラクタ内で呼び出すメソッドは private／final にし、オーバーライドされないようにします。


## 📒 第06章：メソッド（MET）
概要
メソッド設計時の注意点をまとめた章です。リフレクションの乱用、セキュリティマネージャの設定、ファイナライザの誤用など、メソッドレベルでの落とし穴を防ぎます。(JP-CERT)

## MET00-J: セキュリティマネージャやリフレクションを不用意に使用しない
•	解説
*	System.setSecurityManager(...) をプログラム内で呼び出すと、想定外の権限変更やポリシー違反を引き起こす可能性があります。セキュリティ設定は起動時引数（-Djava.security.manager）など外部から管理し、コード内で直接変更しないでください。
*	リフレクションによってプライベートメソッドやフィールドにアクセスすると、クラス内の不変性が崩れ、意図しないパスワードやトークンの読み書きにつながる恐れがあります。リフレクションは最小限にとどめ、可能な限り通常のアクセサ（getter/setter）や設計パターンで代替しましょう。

### •	❌ 悪い例
	public void overrideSecurityManager() {
	    // 実行時に予期しない SecurityException を引き起こす可能性
	    System.setSecurityManager(new SecurityManager());
	}
	
	public void accessPrivateField(Object obj) throws Exception {
	    // リフレクションで private フィールドを強制的に取得
	    Field secretField = obj.getClass().getDeclaredField("secret");
	    secretField.setAccessible(true);
	    Object value = secretField.get(obj);
	    System.out.println("秘密情報: " + value);
	}

### •	✅ 良い例
	// セキュリティマネージャは起動時の JVM 引数で設定し、コード内で触らない
	// java -Djava.security.manager -Djava.security.policy=app.policy MyApp
	
	// private フィールドへのアクセスは、なるべく専用の getter を用意
	public class MyService {
	    private String secret;
	
	    public MyService(String secret) {
	        this.secret = secret;
	    }
	
	    // 必要な場合のみ、限定的に情報を返すメソッドを用意
	    public String getSecretMasked() {
	        return "***" + secret.substring(secret.length() - 4);
	    }
	}

*	セキュリティマネージャは JVM の起動時設定で管理し、コード内では扱わない。
*	リフレクションを使わず、必要に応じたアクセサを用意し、情報漏えいを防ぎます。
 

## 📔 第07章：例外時の動作（ERR）
概要
例外処理の設計ミスによる情報漏えいや不整合状態を防ぐルールをまとめた章です。適切な例外ログ出力やリソースの巻き戻し、カスタム例外の活用などをガイドします。(JP-CERT)

## ERR00-J: 例外メッセージに機密情報を含めない
•	解説
例外時に内部のスタックトレースや機密情報（パスワード、システムパスなど）をログに出力すると、攻撃者に情報を与えてしまいます。ユーザ向けメッセージと、運用者向けのデバッグログは分離し、ログには必要最小限の情報のみを記録してください。

### •	❌ 悪い例
	public void authenticate(String username, String password) throws AuthenticationException {
	    try {
	        // 認証処理
	    } catch (SQLException e) {
	        // 例外詳細をユーザ宛にそのまま表示すると情報漏えいにつながる
	        throw new AuthenticationException("DB error: " + e.getMessage());
	    }
	}

### •	✅ 良い例
	import org.slf4j.Logger;
	import org.slf4j.LoggerFactory;
	
	public class AuthService {
	    private static final Logger logger = LoggerFactory.getLogger(AuthService.class);
	
	    public void authenticate(String username, String password) throws AuthenticationException {
	        try {
	            // 認証処理
	        } catch (SQLException e) {
	            // ユーザ向けには平易なメッセージ、ログには詳細を残す
	            logger.error("データベース接続エラー", e);
	            throw new AuthenticationException("認証中にエラーが発生しました。再度お試しください。");
	        }
	    }
	}

*	logger.error(...) で内部エラー情報を記録し、ユーザには詳細を伏せたメッセージを返します。
 

## ERR01-J: 例外をキャッチしたら必ず処理を行い、握りつぶさない
•	解説
catch (Exception e) { /* 何もしない */ } のように例外を無視すると、バグの原因を特定できず、意図しない動作や情報漏えいのリスクが高まります。例外が発生した場合は、必ずログ出力、さらなるリスロー、あるいは代替処理を行ってシステムを安全な状態に保ちましょう。

### •	❌ 悪い例
	public void process() {
	    try {
	        // 複雑な処理
	    } catch (IOException e) {
	        // 何もしない ⇒ エラーを見逃し、後続処理で NPE 等を招く
	    }
	    // 以降の処理が継続され、予期せぬ挙動を引き起こす可能性あり
	}

### •	✅ 良い例
	public void process() {
	    try {
	        // 複雑な処理
	    } catch (IOException e) {
	        logger.error("ファイル処理中にエラーが発生しました", e);
	        // 適切な代替処理、または例外を上位へスロー
	        throw new RuntimeException("処理を続行できませんでした", e);
	    }
	    // 正常時の処理
	}
*	例外発生時に必ずログを出し、安全な代替処理やリスローを行って、システムの整合性を保ちます。


## 📕 第08章：可視性とアトミック性（VNA）
概要
マルチスレッド環境でのフィールド可視性やアトミック性（原子性）に関するルールをまとめています。volatile、synchronized、AtomicXxx クラスなどを適切に使用し、レースコンディションやデータ不整合を防ぎます。(JP-CERT)

## VNA00-J: 共有変数へは必ず適切な同期機構を使う
•	解説
複数スレッドが同じ変数にアクセスする場合、volatile、synchronized、または java.util.concurrent.atomic パッケージのクラス（例：AtomicInteger）を使用して可視性とアトミック性（排他制御）を確保します。何も対策をしないと、キャッシュの同期ずれや部分的な更新により、予期しない挙動を招きます。

### •	❌ 悪い例
	public class Counter {
	    private int count = 0;
	    public void increment() {
	        count++;
	    }
	    public int getCount() {
	        return count;
	    }
	}
	// 複数スレッドから同時に increment() を呼ぶと、カウントが飛ぶ可能性がある

### •	✅ 良い例
	import java.util.concurrent.atomic.AtomicInteger;
	
	public class Counter {
	    private final AtomicInteger count = new AtomicInteger(0);
	
	    public void increment() {
	        count.incrementAndGet(); // アトミックにインクリメント
	    }
	
	    public int getCount() {
	        return count.get();
	    }
	}

*	AtomicInteger.incrementAndGet() を使うことで、ロックを使わずアトミック性と可視性を確保します。


## 📓 第09章：ロック（LCK）
概要
スレッド間での排他制御（ロック）に関するルールを定め、デッドロックやパフォーマンス低下を防ぎつつ、安全に共有資源を扱います。(JP-CERT)

## LCK00-J: できる限り狭い範囲でロックを取得し、デッドロックを回避する
•	解説
synchronized などで長時間ロックを保持すると、他スレッドの待ちが発生し、システム全体のスループットが低下します。また、異なるロックを順序を変えて取得するとデッドロックが起こります。可能な限りクリティカルセクションを狭くし、ロック取得の順序は常に統一してください。

### •	❌ 悪い例
	public class DataProcessor {
	    private final Object lockA = new Object();
	    private final Object lockB = new Object();
	
	    public void method1() {
	        synchronized (lockA) {
	            // 時間のかかるファイル I/O
	            synchronized (lockB) {
	                // データ処理
	            }
	        }
	    }
	
	    public void method2() {
	        synchronized (lockB) {
	            // 一部処理
	            synchronized (lockA) {
	                // 別の処理
	            }
	        }
	    }
	    // method1 と method2 でロック取得順序が異なるため、デッドロックの恐れあり
	}

### •	✅ 良い例
	public class DataProcessor {
	    private final Object lockA = new Object();
	    private final Object lockB = new Object();
	
	    public void method1() {
	        // クリティカルセクションを可能な限り狭くし、lockA → lockB の順序を統一
	        synchronized (lockA) {
	            // 必要最低限の処理
	        }
	        synchronized (lockB) {
	            // 時間のかかるデータ処理
	        }
	    }
	
	    public void method2() {
	        // lockA → lockB の順序を常に同じにする
	        synchronized (lockA) {
	            synchronized (lockB) {
	                // 処理
	            }
	        }
	    }
	}

*	ロック取得順序を lockA → lockB に統一し、かつクリティカルセクションをできる限り短くしています。
 

## 📘 第10章：スレッド API（THI）
概要
Thread クラスや Runnable 実装など、スレッド生成および操作に関するルールを定めています。スレッドの生死管理や共有変数の可視性などを含み、安全にマルチスレッド処理を設計します。(JP-CERT)

## THI00-J: Thread.stop() や Thread.suspend() を使用しない
•	解説
Thread.stop() や Thread.suspend() は非推奨（deprecated）であり、スレッドを強制終了／一時停止すると内部ロックが解放されず、デッドロックや整合性の破壊を招きます。スレッドを停止する必要がある場合は、フラグを使った協調的キャンセル（interrupt）を行い、安全に終了させてください。

### •	❌ 悪い例
	Thread worker = new Thread(() -> {
	    while (true) {
	        // 長時間処理
	    }
	});
	worker.start();
	// 後から強制停止
	worker.stop(); // 非推奨 ⇒ 不整合を招く恐れがある

### •	✅ 良い例
	public class SafeWorker implements Runnable {
	    private volatile boolean running = true;
	
	    @Override
	    public void run() {
	        while (running) {
	            // 定期的にチェックしつつ作業
	            doWork();
	        }
	    }
	
	    public void stop() {
	        running = false; // 協調的に終了を指示
	    }
	
	    private void doWork() {
	        // 長時間処理
	    }
	}
	
	// 利用側
	SafeWorker workerTask = new SafeWorker();
	Thread workerThread = new Thread(workerTask);
	workerThread.start();
	// 後で終了させる
	workerTask.stop();
	workerThread.join();

*	volatile フラグを使ってループ中に動的に終了を指示し、スレッドを安全に停止します。
 

## 📘 第11章：スレッドプール（TPS）
概要
スレッドプール（ExecutorService）の適切な利用方法を定めています。無制限のスレッド作成やシャットダウン忘れによるリソースリークを防ぎ、例外処理を考慮したタスク設計を推奨します。(JP-CERT)

## TPS00-J: ExecutorService は必ずシャットダウンし、タスク例外をログに残す
•	解説
Executors.newFixedThreadPool(...) などで生成したスレッドプールを使い回した後、shutdown() または shutdownNow() を呼び出さないと JVM が終了できず、リソースリークが発生します。さらに、プール内のタスクで未処理例外が発生するとスレッドが停止してしまう可能性があるため、例外発生時には必ずログを残すか、ThreadFactory で UncaughtExceptionHandler を設定してください。

### •	❌ 悪い例
	ExecutorService executor = Executors.newFixedThreadPool(10);
	executor.submit(() -> {
	    // 例外をキャッチせずに投げる ⇒ スレッドプール内で止まる可能性あり
	    throw new RuntimeException("タスク内で例外発生");
	});
	// シャットダウンを呼ばないので JVM が終了しないリスク

### •	✅ 良い例
	import java.util.concurrent.ExecutorService;
	import java.util.concurrent.Executors;
	import java.util.concurrent.TimeUnit;
	import org.slf4j.Logger;
	import org.slf4j.LoggerFactory;
	
	public class TaskManager {
	    private static final Logger logger = LoggerFactory.getLogger(TaskManager.class);
	
	    private final ExecutorService executor;
	
	    public TaskManager() {
	        this.executor = Executors.newFixedThreadPool(
	            10,
	            r -> {
	                Thread t = new Thread(r);
	                t.setUncaughtExceptionHandler((thread, ex) -> {
	                    // タスク内で未処理例外が発生した場合は必ずログ出力
	                    logger.error("スレッドプール内で例外発生: " + thread.getName(), ex);
	                });
	                return t;
	            }
	        );
	    }
	
	    public void submitTask(Runnable task) {
	        executor.submit(() -> {
	            try {
	                task.run();
	            } catch (Exception e) {
	                // 追加でキャッチしてログを残す
	                logger.error("タスク実行中に例外発生", e);
	                throw e;
	            }
	        });
	    }
	
	    public void shutdown() {
	        executor.shutdown();
	        try {
	            if (!executor.awaitTermination(60, TimeUnit.SECONDS)) {
	                executor.shutdownNow();
	            }
	        } catch (InterruptedException e) {
	            executor.shutdownNow();
	            Thread.currentThread().interrupt();
	        }
	    }
	}

*	ThreadFactory で UncaughtExceptionHandler を設定し、未処理例外をログに残します。
*	最後に shutdown() → awaitTermination(...) → shutdownNow() の順で必ず停止処理を行っています。
 

## 📘 第12章：スレッドの安全性に関する雑則（TSM）
概要
共有変数・イミュータブルオブジェクト・スレッドローカル変数のルールなど、マルチスレッド環境での細かい注意点を定めています。(JP-CERT)

## TSM00-J: 不変オブジェクトを活用し、共有資源の整合性を高める
•	解説
可能な限りオブジェクトを「不変（immutable）」に設計すると、マルチスレッド環境での共有時にロックを不要にでき、デッドロックや可視性問題を避けられます。final フィールドのみを持ち、すべてのフィールドをコンストラクタで確実に初期化することで不変化を保証しましょう。

### •	❌ 悪い例
	public class MutablePoint {
	    public int x;
	    public int y;
	}
	// 複数スレッドから直接フィールドを書き換えられるため整合性が保たれない

### •	✅ 良い例
	public final class ImmutablePoint {
	    private final int x;
	    private final int y;
	
	    public ImmutablePoint(int x, int y) {
	        this.x = x;
	        this.y = y;
	    }
	
	    public int getX() {
	        return x;
	    }
	    public int getY() {
	        return y;
	    }
	}

*	final クラスかつすべてのフィールドを final とし、セッターを持たないことで不変性を保証します。


## 📔 第13章：入出力（FIO）
概要
ファイル／ストリーム操作やネットワーク I/O などに関するルールを定めています。リソースリーク、パス操作、シリアライズデータの取り扱いなどを網羅し、安全な I/O 処理を実現します。(JP-CERT)

## FIO00-J: リソースは必ずクローズし、try-with-resources を活用する
•	解説
ファイルやソケット、ストリームなどは必ずクローズしないと、ファイルハンドルリークやソケットリークにつながります。Java 7 以降は try-with-resources を使って自動的にクローズさせましょう。

### •	❌ 悪い例
	public void readFile(String path) throws IOException {
	    FileInputStream fis = new FileInputStream(path);
	    byte[] data = fis.readAllBytes();
	    // fis.close() を忘れている ⇒ リソースリークの恐れ
	}

### •	✅ 良い例
	public void readFile(String path) throws IOException {
	    try (FileInputStream fis = new FileInputStream(path)) {
	        byte[] data = fis.readAllBytes();
	        // 自動的に fis.close() が呼ばれる
	    }
	}
 
## FIO01-J: ネットワークソケットはタイムアウトを設定し、入力検証を行う
•	解説
ソケットを開設したまま読み込み待ち状態が続くと、DoS（サービス拒否）攻撃を受けやすくなります。接続時・読み込み時には適切なタイムアウトを設定し、ソケットから受信したデータはすべて検証・無害化してから処理します。

### •	❌ 悪い例
	public void handleClient(Socket client) throws IOException {
	    BufferedReader br = new BufferedReader(new InputStreamReader(client.getInputStream()));
	    String line = br.readLine(); // タイムアウトなしで待ち続ける
	    // データの検証を行わずにそのまま処理
	    process(line);
	}

### •	✅ 良い例
	public void handleClient(Socket client) throws IOException {
	    // タイムアウトを 5 秒に設定
	    client.setSoTimeout(5000);
	    try (BufferedReader br = new BufferedReader(new InputStreamReader(client.getInputStream()))) {
	        String line = br.readLine();
	        if (line == null) {
	            throw new IOException("クライアントがデータを送信しませんでした");
	        }
	        // 受け取った文字列を検証・無害化する例
	        String safeLine = sanitize(line);
	        process(safeLine);
	    }
	}
	
	private String sanitize(String input) {
	    // 例: 特定文字を除外する、長さを制限する、正規化してチェックするなど
	    String normalized = Normalizer.normalize(input, Normalizer.Form.NFC);
	    // 英数字と一部記号のみ許可
	    return normalized.replaceAll("[^a-zA-Z0-9 _\\-]", "");
	}


## 📒 第14章：シリアライズ（SER）
概要
Java のシリアライズ／デシリアライズに関するルールを定めています。シリアライズデータをそのまま読み込むとリモートコード実行やオブジェクトの改ざんにつながるため、許可クラスチェックやカスタムの readObject() を必ず実装してください。(JP-CERT)

## SER00-J: デシリアライズするデータは、許可されたクラスのみをインスタンス化する
•	解説
攻撃者が任意のクラスをデシリアライズさせることで、悪意あるオブジェクトを注入しリモートコード実行を行える場合があります。デシリアライズ時に ObjectInputStream.resolveClass() をオーバーライドし、ホワイトリスト方式で許可クラスのみを読み込むように制限します。

### •	❌ 悪い例
	public Object readData(File file) throws IOException, ClassNotFoundException {
	    try (ObjectInputStream ois = new ObjectInputStream(new FileInputStream(file))) {
	        return ois.readObject(); // 任意のクラスを読み込まれる恐れあり
	    }
	}

### •	✅ 良い例
	import java.io.FileInputStream;
	import java.io.IOException;
	import java.io.InvalidClassException;
	import java.io.ObjectInputStream;
	import java.io.ObjectStreamClass;
	
	public Object readData(File file) throws IOException, ClassNotFoundException {
	    try (ObjectInputStream ois = new ObjectInputStream(new FileInputStream(file)) {
	        @Override
	        protected Class<?> resolveClass(ObjectStreamClass desc) throws IOException, ClassNotFoundException {
	            String className = desc.getName();
	            // ホワイトリストに含まれるクラスのみを許可
	            if (!List.of("com.example.SafeClassA", "com.example.SafeClassB").contains(className)) {
	                throw new InvalidClassException("許可されていないクラス: ", className);
	            }
	            return super.resolveClass(desc);
	        }
	    }) {
	        return ois.readObject();
	    }
	}

*	resolveClass(...) をオーバーライドして、ホワイトリストにないクラスは拒否する実装例です。
 

## 📘 第15章：プラットフォームのセキュリティ（SEC）
概要
Java 標準ライブラリや外部ライブラリを使用する際の注意点（危険なメソッド呼び出し制限、暗号化アルゴリズムの正しい利用、ログイン管理など）をガイドします。(JP-CERT)

## SEC00-J: 非推奨の暗号アルゴリズム（MD5, SHA-1 など）を使用しない
•	解説
MD5 や SHA-1 は衝突攻撃が実用化されており、セキュリティ要件を満たせません。SHA-256 以降や、より強力なハッシュ関数（SHA3-256、PBKDF2、bcrypt、scrypt、Argon2）を利用してください。

### •	❌ 悪い例
	import java.security.MessageDigest;
	
	public byte[] hashPassword(String password) throws Exception {
	    MessageDigest md = MessageDigest.getInstance("MD5");
	    return md.digest(password.getBytes(StandardCharsets.UTF_8));
	}

### •	✅ 良い例
	import javax.crypto.SecretKeyFactory;
	import javax.crypto.spec.PBEKeySpec;
	import java.security.SecureRandom;
	import java.util.Base64;
	
	public class PasswordHasher {
	    public String hashPassword(String password, byte[] salt) throws Exception {
	        // PBKDF2 with HmacSHA256 を使った例
	        PBEKeySpec spec = new PBEKeySpec(password.toCharArray(), salt, 65536, 256);
	        SecretKeyFactory skf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
	        byte[] hash = skf.generateSecret(spec).getEncoded();
	        return Base64.getEncoder().encodeToString(hash);
	    }
	
	    public byte[] generateSalt() {
	        byte[] salt = new byte[16];
	        new SecureRandom().nextBytes(salt);
	        return salt;
	    }
	}

*	PBKDF2（反復ハッシュ）＋ HmacSHA256 を使い、十分なストレッチ回数を設定した例です。


## 📙 第16章：実行環境（ENV）
概要
実行時のシステムプロパティ・環境変数の取り扱い、外部設定ファイルの読み込み時における検証など、環境依存のセキュリティリスクを排除するルールをまとめています。(JP-CERT)

## ENV00-J: 環境変数やシステムプロパティを信用せず、検証してから利用する
•	解説
環境変数やシステムプロパティはユーザが容易に変更できるため、直接機密情報として使うとリスクが高まります。値を取得した後は、ホワイトリストや正規表現で検証し、想定外の値が含まれていないかチェックしてから利用します。

### •	❌ 悪い例
	public String getConfigDir() {
	    // user.dir が書き換えられると任意のディレクトリを参照してしまう
	    return System.getProperty("user.dir") + "/config";
	}

### •	✅ 良い例
	public String getConfigDir() {
	    String base = System.getProperty("BASE_DIR", "/opt/myapp");
	    // 英数字と / _ - のみ許可
	    if (!base.matches("^[/a-zA-Z0-9_\\-]+$")) {
	        throw new SecurityException("想定外の BASE_DIR: " + base);
	    }
	    return base + "/config";
	}

*	環境変数やシステムプロパティを取得したら、必ず正規表現で形式をチェックし、想定外であれば拒否します。
 

## 📘 第49章：雑則（MSC）
概要
それまでの章に該当しない汎用的な注意点をまとめた章です。例として、ログ出力の形式統一、不変コレクションの利用、リソースバンドルの管理などがあります。(JP-CERT)

## MSC00-J: ログには必ずログレベルを設定し、構造化ログを心掛ける
•	解説
ログ出力を行う際は、info, warn, error など適切なログレベルを指定し、一貫したフォーマット（例：JSON 形式）で出力すると、ログ解析や監査時に有効です。特にセキュリティログは「誰が・いつ・何をしたか」が明確にわかるように構造化しましょう。

### •	❌ 悪い例
	public void loginUser(String userId) {
	    // ログレベルを明示していないと、何が重要か判別できない
	    System.out.println("User logged in: " + userId);
	}

### •	✅ 良い例
	import org.slf4j.Logger;
	import org.slf4j.LoggerFactory;
	import java.time.Instant;
	
	public class AuditService {
	    private static final Logger logger = LoggerFactory.getLogger(AuditService.class);
	
	    public void loginUser(String userId) {
	        // 構造化ログ（JSON 形式の例）
	        String jsonLog = String.format(
	            "{\"timestamp\":\"%s\",\"event\":\"USER_LOGIN\",\"userId\":\"%s\"}",
	            Instant.now().toString(),
	            userId
	        );
	        logger.info(jsonLog);
	    }
	}

*	JSON 形式など構造化ログにすることで、SIEM やログ解析ツールと連携しやすくなります。
 

# 📝 まとめ
•	本ガイドは、JPCERT/CC の「Java コーディアリングスタンダード CERT/Oracle 版」に基づき、各章ごとにルール ID・タイトル、解説、悪い例、良い例をまとめたものです。
•	実際のプロジェクトでは、以下のポイントを参考にしつつ、チームのコーディング規約に落とし込み、CI／静的解析ツール（FindBugs/SpotBugs, PMD, SonarQube など）と組み合わせて自動チェックを行うとより効果的です。
1.	入力値検証（IDS）：すべての外部入力を検証・正規化・無害化する。
2.	宣言と初期化（DCL）：初期化の循環や曖昧な final フィールドを避ける。
3.	式と数値演算（EXP, NUM）：戻り値のチェック、オーバーフロー／ビット演算ミスを防ぐ。
4.	文字列操作（STR）：大量連結を避け、正規表現や文字列操作時のリスクを回避する。
5.	オブジェクト指向（OBJ）：コンストラクタ内のオーバーライド呼び出しを避け、イミュータブル設計を推奨。
6.	メソッド（MET）：リフレクションやセキュリティマネージャの乱用を避け、責務ごとに明確に設計。
7.	例外処理（ERR）：機密情報を露出しない、安全な例外ログと適切な再スローを行う。
8.	同期・スレッド（VNA, LCK, THI, TPS, TSM）：共有変数の同期、デッドロック回避、不変オブジェクト活用、協調的キャンセルを徹底する。
9.	I/O（FIO）：Try-with-resources でリソースリークを防ぎ、パス検証やタイムアウトを必須にする。
10.	シリアライズ（SER）：デシリアライズ時にホワイトリストを使い、許可クラスのみを読み込む。
11.	プラットフォーム（SEC）：安全な暗号アルゴリズムを使用し、外部ライブラリの脆弱性を監視する。
12.	環境設定（ENV）：環境変数／プロパティを信用せず、入力フォーマットを検証する。
13.	雑則（MSC）：ログは構造化し、監査に耐えうる形で出力するなど、運用時の注意も含める。

•	各ルール ID の詳細な項目やさらに多くの例、補足情報については、以下を参考にしてください。
o	JPCERT/CC「Java セキュアコーディングスタンダード CERT/Oracle 版」ウェブ版
🔗 https://www.jpcert.or.jp/securecoding/materials-java.html (JP-CERT)
o	Fred Long, Dhruv Mohindra, Robert C. Seacord, Dean F. Sutherland, David Svoboda 著, JPCERT/CC 監修『Javaセキュアコーディングスタンダード CERT/Oracle 版』（書籍）
現場の開発プロジェクトに合わせて、本ガイドをベースにコーディング規約として文書化し、レビューや静的解析ルールに組み込むことで、Java アプリケーションのセキュリティを向上させてください。

