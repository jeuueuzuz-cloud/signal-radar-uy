import 'dart:async';
import 'dart:math' as math;
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_blue_plus/flutter_blue_plus.dart';
import 'package:flutter_map/flutter_map.dart';
import 'package:geolocator/geolocator.dart';
import 'package:latlong2/latlong.dart';
import 'package:permission_handler/permission_handler.dart';
import 'package:wifi_scan/wifi_scan.dart';

void main() {
  WidgetsFlutterBinding.ensureInitialized();
  // تثبيت شريط الحالة بلون داكن متناسق مع تصميم الرادار
  SystemChrome.setSystemUIOverlayStyle(
    const SystemUiOverlayStyle(
      statusBarColor: Colors.transparent,
      statusBarIconBrightness: Brightness.light,
    ),
  );
  runApp(const SignalRadarMobileApp());
}

/// التطبيق الرئيسي
class SignalRadarMobileApp extends StatelessWidget {
  const SignalRadarMobileApp({super.key});

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'رادار الإشارات الذكي',
      debugShowCheckedModeBanner: false,
      theme: ThemeData(
        useMaterial3: true,
        brightness: Brightness.dark,
        scaffoldBackgroundColor: const Color(0xFF070B14),
        colorScheme: const ColorScheme.dark(
          primary: Color(0xFF06B6D4),
          secondary: Color(0xFF3B82F6),
          surface: Color(0xFF0D1424),
        ),
      ),
      // فرض الاتجاه من اليمين إلى اليسار للواجهة العربية
      builder: (context, child) {
        return Directionality(
          textDirection: TextDirection.rtl,
          child: child ?? const SizedBox.shrink(),
        );
      },
      home: const RadarHomeScreen(),
    );
  }
}

// =============================================================================
// نماذج البيانات وقواعد التعرف على الهواتف (Models & Fingerprinting Engine)
// =============================================================================

enum SignalSourceType { bluetooth, wifi }

/// نموذج يمثل كل هاتف أو جهاز يتم رصده عبر البلوتوث أو الواي فاي
class DetectedDevice {
  final String id;
  final String name;
  final String brand;
  final String deviceType;
  final String macAddress;
  final SignalSourceType sourceType;
  final String protocolInfo;
  final int rssi;
  final double distanceMeters;
  final LatLng estimatedPosition;
  final double bearingDegrees;
  final bool isRandomizedMac;
  final DateTime lastSeen;

  DetectedDevice({
    required this.id,
    required this.name,
    required this.brand,
    required this.deviceType,
    required this.macAddress,
    required this.sourceType,
    required this.protocolInfo,
    required this.rssi,
    required this.distanceMeters,
    required this.estimatedPosition,
    required this.bearingDegrees,
    required this.isRandomizedMac,
    required this.lastSeen,
  });
}

/// محرك التعرف على نوع الهاتف والشركة المصنّعة عبر:
/// 1) معرّفات شركات البلوتوث القياسية (Bluetooth SIG Company Identifiers)
/// 2) بادئة عنوان الشبكة (MAC OUI)
/// 3) تحليل اسم الجهاز أو نقطة الاتصال (SSID / BLE Name)
class DeviceIdentifierEngine {
  /// جدول حقيقي لأشهر معرّفات الشركات في حزم بث البلوتوث (BLE Manufacturer Data)
  /// يعمل هذا الكشف حتى عندما يستخدم الهاتف عنوان MAC عشوائي لحماية الخصوصية
  static const Map<int, Map<String, String>> bleManufacturerIds = {
    0x004C: {'brand': 'Apple', 'type': 'iPhone / iPad / AirPods'},
    0x0075: {'brand': 'Samsung', 'type': 'هاتف أو جهاز Samsung Galaxy'},
    0x038F: {'brand': 'Xiaomi', 'type': 'هاتف أو جهاز Xiaomi / Redmi'},
    0x027D: {'brand': 'Huawei', 'type': 'هاتف أو جهاز Huawei'},
    0x00E0: {'brand': 'Google', 'type': 'هاتف Google Pixel / Android'},
    0x079A: {'brand': 'OPPO', 'type': 'هاتف OPPO'},
    0x093D: {'brand': 'OnePlus', 'type': 'هاتف OnePlus'},
    0x0822: {'brand': 'Realme', 'type': 'هاتف Realme'},
    0x0006: {'brand': 'Microsoft', 'type': 'حاسوب Windows / Surface'},
    0x012D: {'brand': 'Sony', 'type': 'هاتف أو سماعة Sony'},
    0x0057: {'brand': 'Harman / JBL', 'type': 'سماعة بلوتوث JBL'},
    0x0157: {'brand': 'Anhui Huami (Amazfit)', 'type': 'ساعة ذكية'},
  };

  /// قاعدة بيانات مصغّرة لبادئات عناوين MAC (OUI) للتعرف على أجهزة الواي فاي والبلوتوث
  static const Map<String, Map<String, String>> ouiDatabase = {
    'A4:83:E7': {'brand': 'Apple', 'type': 'هاتف iPhone / جهاز Apple'},
    '3C:22:FB': {'brand': 'Apple', 'type': 'هاتف iPhone / Mac'},
    'F0:98:9D': {'brand': 'Apple', 'type': 'هاتف iPhone'},
    'BC:F5:AC': {'brand': 'Samsung', 'type': 'هاتف Samsung Galaxy'},
    '8C:F5:A3': {'brand': 'Samsung', 'type': 'هاتف Samsung Galaxy'},
    'D0:22:BE': {'brand': 'Samsung', 'type': 'هاتف / جهاز Samsung'},
    '64:CC:2E': {'brand': 'Xiaomi', 'type': 'هاتف Xiaomi / Redmi'},
    '78:11:DC': {'brand': 'Xiaomi', 'type': 'هاتف Xiaomi'},
    '20:F1:7C': {'brand': 'Huawei', 'type': 'هاتف Huawei'},
    '00:E0:FC': {'brand': 'Huawei', 'type': 'هاتف / راوتر Huawei'},
    '3C:28:6D': {'brand': 'Google', 'type': 'هاتف Google Pixel'},
    'AC:37:43': {'brand': 'OPPO', 'type': 'هاتف OPPO'},
    'C0:EE:FB': {'brand': 'OnePlus', 'type': 'هاتف OnePlus'},
    '14:1F:78': {'brand': 'Realme', 'type': 'هاتف Realme'},
    '48:2C:A0': {'brand': 'Infinix / Tecno', 'type': 'هاتف ذكي Android'},
    'F8:1A:67': {'brand': 'TP-Link', 'type': 'راوتر واي فاي'},
    'C0:25:E9': {'brand': 'TP-Link', 'type': 'راوتر واي فاي'},
    'E4:8D:8C': {'brand': 'MikroTik', 'type': 'نقطة وصول / راوتر'},
  };

  /// التحقق مما إذا كان عنوان MAC عشوائياً (Locally Administered Address)
  static bool isMacRandomized(String mac) {
    final cleaned = mac.replaceAll(RegExp(r'[^0-9A-Fa-f]'), '');
    if (cleaned.length < 2) return false;
    final secondHex = int.tryParse(cleaned[1], radix: 16);
    if (secondHex == null) return false;
    return (secondHex & 2) != 0;
  }

  /// التعرف الذكي على الشركة ونوع الهاتف اعتماداً على كافة القرائن المتاحة
  static ({String brand, String deviceType}) identifyDevice({
    required String rawName,
    required String mac,
    Map<int, List<int>>? bleManufacturerData,
    required SignalSourceType sourceType,
  }) {
    // 1. الأولوية الأولى: فحص معرّف الشركة في إشارة البلوتوث
    if (bleManufacturerData != null && bleManufacturerData.isNotEmpty) {
      for (final companyId in bleManufacturerData.keys) {
        final match = bleManufacturerIds[companyId];
        if (match != null) {
          return (
            brand: match['brand']!,
            deviceType: _refineTypeFromName(rawName, match['type']!),
          );
        }
      }
    }

    // 2. الأولوية الثانية: فحص بادئة MAC OUI
    final cleanMac = mac.toUpperCase();
    if (cleanMac.length >= 8) {
      final oui = cleanMac.substring(0, 8);
      final match = ouiDatabase[oui];
      if (match != null) {
        return (
          brand: match['brand']!,
          deviceType: _refineTypeFromName(rawName, match['type']!),
        );
      }
    }

    // 3. الأولوية الثالثة: تحليل اسم الجهاز أو اسم نقطة الاتصال (Hotspot / BLE Name)
    final lower = rawName.toLowerCase();
    if (lower.contains('iphone')) {
      return (brand: 'Apple', deviceType: 'هاتف iPhone');
    }
    if (lower.contains('ipad')) {
      return (brand: 'Apple', deviceType: 'جهاز iPad');
    }
    if (lower.contains('airpods') || lower.contains('macbook')) {
      return (brand: 'Apple', deviceType: 'جهاز Apple');
    }
    if (lower.contains('galaxy') || lower.contains('samsung')) {
      return (brand: 'Samsung', deviceType: 'هاتف Samsung Galaxy');
    }
    if (lower.contains('redmi') ||
        lower.contains('poco') ||
        lower.contains('xiaomi')) {
      return (brand: 'Xiaomi', deviceType: 'هاتف Xiaomi / Redmi');
    }
    if (lower.contains('huawei') || lower.contains('honor')) {
      return (brand: 'Huawei / Honor', deviceType: 'هاتف Huawei');
    }
    if (lower.contains('oppo') || lower.contains('reno')) {
      return (brand: 'OPPO', deviceType: 'هاتف OPPO');
    }
    if (lower.contains('realme')) {
      return (brand: 'Realme', deviceType: 'هاتف Realme');
    }
    if (lower.contains('pixel')) {
      return (brand: 'Google', deviceType: 'هاتف Google Pixel');
    }
    if (lower.contains('infinix') || lower.contains('tecno')) {
      return (brand: 'Transsion', deviceType: 'هاتف Infinix / Tecno');
    }

    // القيمة الافتراضية في حال عدم توفر بصمة واضحة
    if (sourceType == SignalSourceType.wifi) {
      return (
        brand: isMacRandomized(mac) ? 'جهاز محمي (MAC عشوائي)' : 'شبكة / جهاز Wi-Fi',
        deviceType: 'نقطة اتصال أو راوتر Wi-Fi',
      );
    }
    return (
      brand: isMacRandomized(mac) ? 'هاتف محمي (MAC عشوائي)' : 'جهاز بلوتوث',
      deviceType: 'جهاز بلوتوث قريب (BLE)',
    );
  }

  /// تحسين وصف نوع الجهاز إذا كان الاسم يوضح موديل الهاتف مباشرة
  static String _refineTypeFromName(String rawName, String defaultType) {
    final lower = rawName.toLowerCase();
    if (lower.contains('iphone')) return 'هاتف iPhone';
    if (lower.contains('galaxy')) return 'هاتف Samsung Galaxy';
    if (lower.contains('redmi')) return 'هاتف Redmi';
    if (lower.contains('airpods') || lower.contains('buds')) {
      return 'سماعة لاسلكية';
    }
    if (lower.contains('watch') || lower.contains('band')) {
      return 'ساعة / سوار ذكي';
    }
    return defaultType;
  }

  /// حساب المسافة التقديرية بالمتر اعتماداً على قوة الإشارة (RSSI)
  static double estimateDistanceMeters(
    int rssi, {
    int txPower = -59,
    double pathLossExponent = 2.5,
  }) {
    if (rssi >= 0) return 1.0;
    final exponent = (txPower - rssi) / (10.0 * pathLossExponent);
    final meters = math.pow(10, exponent).toDouble();
    return meters.clamp(0.5, 120.0);
  }

  /// توليد زاوية اتجاه ثابتة لكل جهاز بناءً على معرّفه لضمان استقراره على الخريطة
  static double stableBearingFromId(String id) {
    int hash = 0;
    for (int i = 0; i < id.length; i++) {
      hash = (hash * 31 + id.codeUnitAt(i)) & 0x7FFFFFFF;
    }
    return (hash % 360).toDouble();
  }

  /// حساب إحداثيات جغرافية (LatLng) تبعد مسافة محددة بالمتر عن نقطة الأصل
  static LatLng offsetPosition(
    LatLng origin,
    double distanceMeters,
    double bearingDegrees,
  ) {
    const double earthRadius = 6378137.0;
    final double bearingRad = bearingDegrees * math.pi / 180.0;
    final double latRad = origin.latitude * math.pi / 180.0;

    final double dLat = (distanceMeters * math.cos(bearingRad)) / earthRadius;
    final double dLng = (distanceMeters * math.sin(bearingRad)) /
        (earthRadius * math.cos(latRad));

    return LatLng(
      origin.latitude + (dLat * 180.0 / math.pi),
      origin.longitude + (dLng * 180.0 / math.pi),
    );
  }
}

// =============================================================================
// الشاشة الرئيسية للتطبيق (الخريطة + الرادار + قائمة الأجهزة)
// =============================================================================

class RadarHomeScreen extends StatefulWidget {
  const RadarHomeScreen({super.key});

  @override
  State<RadarHomeScreen> createState() => _RadarHomeScreenState();
}

class _RadarHomeScreenState extends State<RadarHomeScreen> {
  final MapController _mapController = MapController();

  // الموقع الافتراضي الاحتياطي قبل قفل GPS
  LatLng _userPosition = const LatLng(35.1975, -0.6300);
  bool _gpsReady = false;
  bool _isScanning = false;
  bool _isDarkMap = true;
  String _statusText = 'اضغط على "بدء المسح" لفحص البلوتوث والواي فاي';

  // فلتر العرض: all | bluetooth | wifi
  String _activeFilter = 'all';
  String _searchQuery = '';

  // الأجهزة المرصودة مخزّنة حسب المعرّف لمنع التكرار
  final Map<String, DetectedDevice> _devicesMap = {};
  String? _selectedDeviceId;

  // الاشتراكات والمؤقتات
  StreamSubscription<List<ScanResult>>? _bleScanSub;
  StreamSubscription<Position>? _gpsSub;
  Timer? _wifiPeriodicTimer;

  @override
  void initState() {
    super.initState();
    _initializePermissionsAndLocation();
  }

  @override
  void dispose() {
    _stopAllScans();
    _gpsSub?.cancel();
    super.dispose();
  }

  /// طلب الصلاحيات المطلوبة وتحديد الموقع الجغرافي الحقيقي
  Future<void> _initializePermissionsAndLocation() async {
    try {
      await [
        Permission.locationWhenInUse,
        Permission.bluetoothScan,
        Permission.bluetoothConnect,
        Permission.nearbyWifiDevices,
      ].request();

      final serviceEnabled = await Geolocator.isLocationServiceEnabled();
      if (!serviceEnabled) {
        _showSnack('يرجى تفعيل خدمة الموقع (GPS) لعرض موقعك وفحص الشبكات.', isError: true);
        return;
      }

      // جلب الموقع الحالي
      final pos = await Geolocator.getCurrentPosition(
        locationSettings: const LocationSettings(
          accuracy: LocationAccuracy.high,
        ),
      );

      if (!mounted) return;
      setState(() {
        _userPosition = LatLng(pos.latitude, pos.longitude);
        _gpsReady = true;
        _statusText = 'تم تحديد موقعك (دقة ${pos.accuracy.round()} م) • جاهز للمسح';
      });
      _mapController.move(_userPosition, 18.0);

      // تتبع تحديثات الموقع أثناء تحرك المستخدم
      _gpsSub = Geolocator.getPositionStream(
        locationSettings: const LocationSettings(
          accuracy: LocationAccuracy.high,
          distanceFilter: 3,
        ),
      ).listen((updatedPos) {
        if (!mounted) return;
        setState(() {
          _userPosition = LatLng(updatedPos.latitude, updatedPos.longitude);
        });
      });
    } catch (e) {
      if (!mounted) return;
      setState(() {
        _statusText = 'تعذر الوصول إلى GPS - يتم استخدام الموقع الافتراضي';
      });
    }
  }

  /// تشغيل أو إيقاف الفحص الشامل (بلوتوث + واي فاي)
  Future<void> _toggleRadarScan() async {
    if (_isScanning) {
      await _stopAllScans();
      return;
    }

    // التأكد من الصلاحيات قبل المسح
    final locStatus = await Permission.locationWhenInUse.request();
    final btScanStatus = await Permission.bluetoothScan.request();
    await Permission.bluetoothConnect.request();
    await Permission.nearbyWifiDevices.request();

    if (!locStatus.isGranted && !btScanStatus.isGranted) {
      _showSnack('الصلاحيات مطلوبة ليتمكن الهاتف من مسح البلوتوث والواي فاي.', isError: true);
      return;
    }

    setState(() {
      _isScanning = true;
      _statusText = 'جاري مسح إشارات البلوتوث والواي فاي القريبة...';
    });

    // 1. بدء الفحص الحقيقي عبر البلوتوث (BLE)
    await _startBluetoothScan();

    // 2. بدء الفحص الحقيقي لشبكات ونقاط اتصال الواي فاي (Android)
    await _runSingleWifiScan();
    _wifiPeriodicTimer?.cancel();
    _wifiPeriodicTimer = Timer.periodic(
      const Duration(seconds: 6),
      (_) => _runSingleWifiScan(),
    );
  }

  /// بدء مسح البلوتوث الحقيقي عبر FlutterBluePlus
  Future<void> _startBluetoothScan() async {
    try {
      final adapterState = await FlutterBluePlus.adapterState.first;
      if (adapterState != BluetoothAdapterState.on) {
        _showSnack('البلوتوث مغلق! قم بتشغيله لرصد الهواتف القريبة.', isError: true);
        return;
      }

      await _bleScanSub?.cancel();
      _bleScanSub = FlutterBluePlus.scanResults.listen((results) {
        if (!mounted) return;

        bool changed = false;
        for (final r in results) {
          final mac = r.device.remoteId.str;
          final advName = r.advertisementData.advName.trim();
          final platName = r.device.platformName.trim();
          final displayName = advName.isNotEmpty
              ? advName
              : (platName.isNotEmpty ? platName : 'جهاز بلوتوث غير مسمى');

          // التعرف على نوع الهاتف من حزمة الإعلان و MAC
          final identity = DeviceIdentifierEngine.identifyDevice(
            rawName: displayName,
            mac: mac,
            bleManufacturerData: r.advertisementData.manufacturerData,
            sourceType: SignalSourceType.bluetooth,
          );

          final txPower = r.advertisementData.txPowerLevel ?? -59;
          final distance = DeviceIdentifierEngine.estimateDistanceMeters(
            r.rssi,
            txPower: txPower,
            pathLossExponent: 2.4,
          );

          final id = 'ble_$mac';
          final bearing = DeviceIdentifierEngine.stableBearingFromId(id);
          final estPos = DeviceIdentifierEngine.offsetPosition(
            _userPosition,
            distance,
            bearing,
          );

          final mfgIdsText = r.advertisementData.manufacturerData.keys
              .map((k) => '0x${k.toRadixString(16).toUpperCase().padLeft(4, '0')}')
              .join(', ');

          _devicesMap[id] = DetectedDevice(
            id: id,
            name: displayName,
            brand: identity.brand,
            deviceType: identity.deviceType,
            macAddress: mac,
            sourceType: SignalSourceType.bluetooth,
            protocolInfo: mfgIdsText.isNotEmpty
                ? 'BLE • معرّف الشركة: $mfgIdsText'
                : 'Bluetooth Low Energy (BLE)',
            rssi: r.rssi,
            distanceMeters: distance,
            estimatedPosition: estPos,
            bearingDegrees: bearing,
            isRandomizedMac: DeviceIdentifierEngine.isMacRandomized(mac),
            lastSeen: DateTime.now(),
          );
          changed = true;
        }

        if (changed) {
          setState(() {
            _statusText = 'مسح نشط • تم رصد ${_devicesMap.length} جهاز قريب';
          });
        }
      });

      // تشغيل مسح البلوتوث لمدة 25 ثانية
      await FlutterBluePlus.startScan(
        timeout: const Duration(seconds: 25),
        androidUsesFineLocation: true,
      );
    } catch (e) {
      _showSnack('تعذر بدء مسح البلوتوث: $e', isError: true);
    }
  }

  /// تنفيذ دورة مسح حقيقية لشبكات ونقاط اتصال الواي فاي (يعمل على Android)
  Future<void> _runSingleWifiScan() async {
    try {
      final canScan = await WiFiScan.instance.canStartScan();
      if (canScan == CanStartScan.yes) {
        await WiFiScan.instance.startScan();
      }

      final canGet = await WiFiScan.instance.canGetScannedResults();
      if (canGet != CanGetScannedResults.yes) return;

      final List<WiFiAccessPoint> accessPoints =
          await WiFiScan.instance.getScannedResults();

      if (!mounted) return;

      for (final ap in accessPoints) {
        final bssid = ap.bssid.toUpperCase();
        final ssid = ap.ssid.trim().isNotEmpty ? ap.ssid.trim() : 'شبكة مخفية';

        final identity = DeviceIdentifierEngine.identifyDevice(
          rawName: ssid,
          mac: bssid,
          sourceType: SignalSourceType.wifi,
        );

        final distance = DeviceIdentifierEngine.estimateDistanceMeters(
          ap.level,
          txPower: -45,
          pathLossExponent: 2.7,
        );

        final id = 'wifi_$bssid';
        final bearing = DeviceIdentifierEngine.stableBearingFromId(id);
        final estPos = DeviceIdentifierEngine.offsetPosition(
          _userPosition,
          distance,
          bearing,
        );

        final band = ap.frequency >= 5900
            ? '6 GHz'
            : (ap.frequency >= 4900 ? '5 GHz' : '2.4 GHz');

        _devicesMap[id] = DetectedDevice(
          id: id,
          name: ssid,
          brand: identity.brand,
          deviceType: identity.deviceType,
          macAddress: bssid,
          sourceType: SignalSourceType.wifi,
          protocolInfo: 'Wi-Fi ($band • ${ap.frequency} MHz)',
          rssi: ap.level,
          distanceMeters: distance,
          estimatedPosition: estPos,
          bearingDegrees: bearing,
          isRandomizedMac: DeviceIdentifierEngine.isMacRandomized(bssid),
          lastSeen: DateTime.now(),
        );
      }

      setState(() {
        _statusText = 'مسح نشط • تم رصد ${_devicesMap.length} جهاز وشبكة';
      });
    } catch (_) {
      // في أجهزة iOS لا يسمح النظام بمسح شبكات الواي فاي، فيستمر البلوتوث بسلاسة
    }
  }

  /// إيقاف كافة عمليات المسح لتوفير البطارية
  Future<void> _stopAllScans() async {
    _wifiPeriodicTimer?.cancel();
    _wifiPeriodicTimer = null;
    await _bleScanSub?.cancel();
    _bleScanSub = null;
    try {
      await FlutterBluePlus.stopScan();
    }
