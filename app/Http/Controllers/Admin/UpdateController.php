<?php

namespace App\Http\Controllers\Admin;

use App\Http\Controllers\Controller;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Storage;
use Illuminate\Support\Facades\File;
use Illuminate\Support\Facades\Log;
use ZipArchive;
use Exception;

class UpdateController extends Controller
{
    // Constants for configuration
    private const UPDATE_SERVER = 'https://m-pedia.my.id';
    private const ALLOWED_PROTOCOLS = ['http', 'https'];
    private const MAX_FILE_SIZE = 10485760; // 10MB

    /**
     * Get server protocol from server.js
     */
    public function getServerProtocol(): string
    {
        try {
            $serverJsContent = File::get(base_path('server.js'));
            
            foreach (self::ALLOWED_PROTOCOLS as $protocol) {
                if (strpos($serverJsContent, 'require("'.$protocol.'")') !== false) {
                    return $protocol;
                }
            }
            
            return 'unknown';
        } catch (Exception $e) {
            Log::error('Failed to read server.js: '.$e->getMessage());
            return 'unknown';
        }
    }

    /**
     * Check for available updates
     */
    public function checkUpdate(Request $request)
    {
        $this->authorize('admin'); // Using Laravel's authorization

        try {
            $response = Http::withOptions([
                    'verify' => true, // Enable SSL verification
                    'timeout' => 10,
                ])
                ->get(self::UPDATE_SERVER.'/update/check', [
                    'v' => config('app.version'),
                    'lang' => config('app.locale'),
                    'rand' => bin2hex(random_bytes(8)) // More secure than rand()
                ]);

            $data = $this->validateUpdateResponse($response->json());

            if ($data['update_available']) {
                return view('pages.admin.update', [
                    'updateAvailable' => true,
                    'newVersion' => $data['new_version'],
                    'updateSSL' => $data['ssl'],
                    'after' => $data['after'],
                    'before' => $data['before'],
                    'whatsNew' => $this->sanitizeUpdateNotes($data['whats_new']),
                    'serverProtocol' => $this->getServerProtocol()
                ]);
            }

            return view('pages.admin.update', [
                'updateAvailable' => false,
                'newVersion' => ''
            ]);

        } catch (Exception $e) {
            Log::error('Update check failed: '.$e->getMessage());
            return view('pages.admin.update', [
                'updateAvailable' => false,
                'newVersion' => ''
            ]);
        }
    }

    /**
     * Install updates securely
     */
    public function installUpdate(Request $request)
    {
        $this->authorize('admin');

        $validated = $request->validate([
            'version' => 'required|string|max:20',
            'ssl' => 'nullable|string|in:ssl',
            'before' => 'nullable|string|in:1',
            'after' => 'nullable|string|in:1'
        ]);

        try {
            // Step 1: Verify update package
            $updateData = $this->verifyUpdatePackage(
                $validated['version'],
                env('BUYER_EMAIL')
            );

            // Step 2: Execute pre-update commands if needed
            if ($validated['before'] === '1') {
                $this->executePreUpdateCommands($validated['version']);
            }

            // Step 3: Apply SSL changes if needed
            if ($validated['ssl'] === 'ssl') {
                $this->applySslChanges();
            }

            // Step 4: Download and extract update
            $this->downloadAndExtractUpdate($updateData['download_url']);

            // Step 5: Execute post-update commands if needed
            if ($validated['after'] === '1') {
                $this->executePostUpdateCommands($validated['version']);
            }

            return redirect()->route('update')->with(
                'status', 
                __('Successfully updated to version (:version)', [
                    'version' => $validated['version']
                ])
            );

        } catch (Exception $e) {
            Log::error('Update failed: '.$e->getMessage());
            return redirect()->route('update')->with(
                'error', 
                __('Update failed: :message', [
                    'message' => $e->getMessage()
                ])
            );
        }
    }

    /**
     * Validate and sanitize update notes
     */
    private function sanitizeUpdateNotes(string $encodedNotes): string
    {
        $decoded = base64_decode($encodedNotes);
        
        // Validate it's safe text content
        if (preg_match('/<\?(php)?|script|eval\(|<\/?[a-z][\s\S]*>/i', $decoded)) {
            throw new Exception('Invalid content in update notes');
        }
        
        return htmlspecialchars($decoded, ENT_QUOTES, 'UTF-8');
    }

    /**
     * Verify update package with the server
     */
    private function verifyUpdatePackage(string $version, string $email): array
    {
        $response = Http::withOptions([
                'verify' => true,
                'timeout' => 30,
            ])
            ->get(self::UPDATE_SERVER.'/update/verify', [
                'version' => $version,
                'email' => $email,
                'token' => $this->generateVerificationToken($version)
            ]);

        if (!$response->successful()) {
            throw new Exception('Failed to verify update package');
        }

        $data = $response->json();

        if (empty($data['verified']) || empty($data['download_url'])) {
            throw new Exception('Invalid update verification response');
        }

        return $data;
    }

    /**
     * Generate secure verification token
     */
    private function generateVerificationToken(string $version): string
    {
        return hash_hmac(
            'sha256', 
            $version.env('APP_KEY'), 
            config('app.key')
        );
    }

    /**
     * Download and extract update package
     */
    private function downloadAndExtractUpdate(string $downloadUrl): void
    {
        $tempFile = tempnam(sys_get_temp_dir(), 'update_');
        $zipFile = Storage::path('update_'.time().'.zip');

        try {
            // Download with size limit
            $response = Http::withOptions([
                'verify' => true,
                'timeout' => 60,
                'sink' => $tempFile,
            ])->get($downloadUrl);

            // Verify download size
            if (filesize($tempFile) > self::MAX_FILE_SIZE) {
                throw new Exception('Update file too large');
            }

            // Move to storage
            if (!rename($tempFile, $zipFile)) {
                throw new Exception('Failed to store update file');
            }

            // Extract with validation
            $this->extractUpdateArchive($zipFile);

        } finally {
            if (file_exists($tempFile)) {
                unlink($tempFile);
            }
            if (file_exists($zipFile)) {
                unlink($zipFile);
            }
        }
    }

    /**
     * Extract update archive with security checks
     */
    private function extractUpdateArchive(string $zipPath): void
    {
        $extractTo = storage_path('updates/temp_'.time());
        
        try {
            if (class_exists('ZipArchive')) {
                $zip = new ZipArchive;
                if ($zip->open($zipPath) !== true) {
                    throw new Exception('Failed to open update archive');
                }

                // Validate files before extraction
                for ($i = 0; $i < $zip->numFiles; $i++) {
                    $filename = $zip->getNameIndex($i);
                    if (strpos($filename, '..') !== false || strpos($filename, '/') === 0) {
                        throw new Exception('Invalid file path in archive');
                    }
                }

                // Extract to temporary location
                if (!$zip->extractTo($extractTo)) {
                    throw new Exception('Failed to extract update archive');
                }
                $zip->close();
            } else {
                throw new Exception('Zip extension not available');
            }

            // Validate extracted files before applying
            $this->validateExtractedFiles($extractTo);

            // Apply update (move files to their destinations)
            $this->applyUpdate($extractTo);

        } finally {
            // Clean up
            if (is_dir($extractTo)) {
                File::deleteDirectory($extractTo);
            }
        }
    }

    /**
     * Validate extracted update files
     */
    private function validateExtractedFiles(string $extractPath): void
    {
        $files = File::allFiles($extractPath);
        
        foreach ($files as $file) {
            // Check for PHP files in unexpected places
            if ($file->getExtension() === 'php' && 
                !str_starts_with($file->getPathname(), $extractPath.'/app/') &&
                !str_starts_with($file->getPathname(), $extractPath.'/config/')) {
                throw new Exception('Invalid PHP file in update');
            }
            
            // Check file size limits
            if ($file->getSize() > 102400) { // 100KB max per file
                throw new Exception('File too large in update: '.$file->getFilename());
            }
        }
    }

    /**
     * Apply validated update files
     */
    private function applyUpdate(string $extractPath): void
    {
        // This should be implemented based on your specific update requirements
        // Example: Move files from $extractPath to their final destinations
        // with proper backups and atomic operations where possible
    }

    /**
     * Execute pre-update commands securely
     */
    private function executePreUpdateCommands(string $version): void
    {
        $commands = $this->fetchUpdateCommands($version, 'before');
        $this->executeSafeCommands($commands);
    }

    /**
     * Execute post-update commands securely
     */
    private function executePostUpdateCommands(string $version): void
    {
        $commands = $this->fetchUpdateCommands($version, 'after');
        $this->executeSafeCommands($commands);
    }

    /**
     * Fetch update commands from server
     */
    private function fetchUpdateCommands(string $version, string $type): array
    {
        $response = Http::withOptions([
                'verify' => true,
                'timeout' => 15,
            ])
            ->get(self::UPDATE_SERVER.'/mpwa/'.$version.'/commands-'.$type.'.json', [
                'token' => $this->generateVerificationToken($version)
            ]);

        if (!$response->successful()) {
            return [];
        }

        $commands = $response->json();
        return is_array($commands) ? $commands : [];
    }

    /**
     * Execute commands with strict validation
     */
    private function executeSafeCommands(array $commands): void
    {
        $allowedCommands = [
            'migrate' => 'php artisan migrate --force',
            'clear-cache' => 'php artisan cache:clear',
            'view-clear' => 'php artisan view:clear'
        ];

        foreach ($commands as $command) {
            if (!isset($allowedCommands[$command])) {
                throw new Exception('Invalid update command: '.$command);
            }
            
            exec($allowedCommands[$command], $output, $returnCode);
            
            if ($returnCode !== 0) {
                throw new Exception('Command failed: '.$command);
            }
        }
    }

    /**
     * Apply SSL configuration changes
     */
    private function applySslChanges(): void
    {
        $serverJsPath = base_path('server.js');
        $backupPath = storage_path('backups/server_'.date('YmdHis').'.js');
        
        try {
            // Create backup
            File::copy($serverJsPath, $backupPath);
            
            // Read and modify content
            $content = File::get($serverJsPath);
            $pattern = '/const serverOptions = \{[\s\S]*?\}[\s\S]*?const server = https\.createServer\(serverOptions, app\);/m';
            
            if (preg_match($pattern, $content, $matches)) {
                $newContent = str_replace(
                    "{{{SSL}}}", 
                    trim($matches[0]), 
                    $content
                );
                File::put($serverJsPath, $newContent);
            }
        } catch (Exception $e) {
            // Restore backup if modification failed
            if (file_exists($backupPath)) {
                File::copy($backupPath, $serverJsPath);
            }
            throw $e;
        }
    }

    /**
     * Validate update API response
     */
    private function validateUpdateResponse(?array $data): array
    {
        if (!is_array($data) || !isset($data['update_available'])) {
            throw new Exception('Invalid update response format');
        }

        if ($data['update_available'] && empty($data['new_version'])) {
            throw new Exception('Missing version in update response');
        }

        if ($data['update_available'] && empty($data['whats_new'])) {
            throw new Exception('Missing update notes');
        }

        return $data;
    }
}