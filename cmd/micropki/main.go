package main

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
	"MicroPKI/internal/ca"
	"MicroPKI/internal/logger"
)

var (
	rootCmd = &cobra.Command{
		Use:   "micropki",
		Short: "MicroPKI - минимальная реализация PKI",
		Long:  `MicroPKI - это образовательный проект по созданию инфраструктуры открытых ключей.`,
	}

	caCmd = &cobra.Command{
		Use:   "ca",
		Short: "Управление удостоверяющими центрами",
	}

	caInitCmd = &cobra.Command{
		Use:   "init",
		Short: "Инициализация корневого УЦ",
		RunE:  runCAInit,
	}

	subject         string
	keyType         string
	keySize         int
	passphraseFile  string
	outDir          string
	validityDays    int
	logFile         string
	force           bool
)

func init() {
	rootCmd.AddCommand(caCmd)
	caCmd.AddCommand(caInitCmd)

	caInitCmd.Flags().StringVar(&subject, "subject", "", "Distinguished Name (e.g., /CN=My Root CA или CN=My Root CA,O=Demo,C=US)")
	caInitCmd.Flags().StringVar(&keyType, "key-type", "rsa", "Тип ключа: rsa или ecc")
	caInitCmd.Flags().IntVar(&keySize, "key-size", 4096, "Размер ключа в битах (для RSA: 4096, для ECC: 384)")
	caInitCmd.Flags().StringVar(&passphraseFile, "passphrase-file", "", "Файл с парольной фразой для шифрования ключа")
	caInitCmd.Flags().StringVar(&outDir, "out-dir", "./pki", "Выходная директория")
	caInitCmd.Flags().IntVar(&validityDays, "validity-days", 3650, "Срок действия в днях (по умолчанию 10 лет)")
	caInitCmd.Flags().StringVar(&logFile, "log-file", "", "Файл для логов (по умолчанию stderr)")
	caInitCmd.Flags().BoolVar(&force, "force", false, "Принудительная перезапись существующих файлов")

	caInitCmd.MarkFlagRequired("subject")
	caInitCmd.MarkFlagRequired("passphrase-file")
}

func runCAInit(cmd *cobra.Command, args []string) error {
	if err := logger.Init(logFile); err != nil {
		return fmt.Errorf("Ошибка инициализации логгера: %w", err)
	}

	if err := validateCAInitParams(); err != nil {
		logger.Error("%v", err)
		return err
	}

	if !force {
		if err := checkExistingFiles(); err != nil {
			logger.Error("%v", err)
			return err
		}
	}

	rootCA, err := ca.NewRootCA(
		subject,
		keyType,
		keySize,
		passphraseFile,
		outDir,
		validityDays,
		force,
	)
	if err != nil {
		logger.Error("Ошибка создания корневого УЦ: %v", err)
		return fmt.Errorf("ошибка создания корневого УЦ: %w", err)
	}

	if err := rootCA.Initialize(); err != nil {
		logger.Error("Ошибка инициализации УЦ: %v", err)
		return fmt.Errorf("ошибка инициализации УЦ: %w", err)
	}

	logger.Info("Корневой УЦ успешно создан в директории: %s", outDir)
	fmt.Printf("\nКорневой УЦ успешно создан!\n")
	fmt.Printf("   Сертификат: %s\n", filepath.Join(outDir, "certs", "ca.cert.pem"))
	fmt.Printf("   Ключ: %s\n", filepath.Join(outDir, "private", "ca.key.pem"))
	fmt.Printf("   Политика: %s\n", filepath.Join(outDir, "policy.txt"))
	fmt.Printf("\nДля проверки сертификата выполните:\n")
	fmt.Printf("  openssl x509 -in %s -text -noout\n", filepath.Join(outDir, "certs", "ca.cert.pem"))
	fmt.Printf("  openssl verify -CAfile %s %s\n", 
		filepath.Join(outDir, "certs", "ca.cert.pem"),
		filepath.Join(outDir, "certs", "ca.cert.pem"))
	
	return nil
}

func validateCAInitParams() error {
	if subject == "" {
		return fmt.Errorf("subject не может быть пустым")
	}

	if keyType != "rsa" && keyType != "ecc" {
		return fmt.Errorf("key-type должен быть 'rsa' или 'ecc', получено: %s", keyType)
	}

	if keyType == "rsa" && keySize != 4096 {
		return fmt.Errorf("Для RSA размер ключа должен быть 4096 бит, получено: %d", keySize)
	}
	if keyType == "ecc" && keySize != 384 {
		return fmt.Errorf("Для ECC размер ключа должен быть 384 бита (P-384), получено: %d", keySize)
	}

	if _, err := os.Stat(passphraseFile); os.IsNotExist(err) {
		return fmt.Errorf("Файл с парольной фразой не существует: %s", passphraseFile)
	}

	passphrase, err := os.ReadFile(passphraseFile)
	if err != nil {
		return fmt.Errorf("Ошибка чтения файла с парольной фразой: %w", err)
	}
	if len(passphrase) == 0 {
		return fmt.Errorf("Файл с парольной фразой пуст")
	}

	if validityDays <= 0 {
		return fmt.Errorf("validity-days должен быть положительным числом, получено: %d", validityDays)
	}
	if validityDays > 36500 {
		return fmt.Errorf("validity-days не может превышать 36500 дней (100 лет)")
	}

	return nil
}

func checkExistingFiles() error {
	keyPath := filepath.Join(outDir, "private", "ca.key.pem")
	certPath := filepath.Join(outDir, "certs", "ca.cert.pem")
	policyPath := filepath.Join(outDir, "policy.txt")

	existing := []string{}
	if _, err := os.Stat(keyPath); err == nil {
		existing = append(existing, keyPath)
	}
	if _, err := os.Stat(certPath); err == nil {
		existing = append(existing, certPath)
	}
	if _, err := os.Stat(policyPath); err == nil {
		existing = append(existing, policyPath)
	}

	if len(existing) > 0 {
		fmt.Println("Следующие файлы уже существуют:")
		for _, f := range existing {
			fmt.Printf("  %s\n", f)
		}
		return fmt.Errorf("Используйте --force для принудительной перезаписи")
	}
	return nil
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}
