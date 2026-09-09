// Локальный CI Asmodeus на http://localhost:8081. Порт с .github/workflows
// у Asmodeus нет — пайплайн собран по конвенциям Ferrum (см. его Jenkinsfile),
// на которые ориентирован сам воркспейс (ARCHITECTURE.md).
//
// Отличия от Ferrum намеренные — у Asmodeus сейчас нет ни eBPF-датапейса с
// ядерными тестами, ни Dockerfile'ов/деплоя, ни k8s. Поэтому здесь только то,
// что этот воркспейс действительно умеет доказать: SAST-гейт, fmt/clippy/test
// и supply-chain. Стадии образов/линковки под QEMU и датапейс не портированы —
// добавлять их вместе с соответствующим кодом, а не заранее.
//
// Сборка в docker.image().inside(): CARGO_TARGET_DIR обязан быть named volume.
// Bind-mount macOS/VirtioFS ломает cargo недетерминированно (E0463 can't find
// crate) — это оплачено отладкой на Ferrum, не повторять на bind-mount'е.
//
// Фича `asmodeus-runner/ebpf` (aya) — Linux-only и требует ядра в рантайме,
// поэтому её только КОМПИЛИРУЕМ через clippy (ловим ошибки feature-gated кода),
// но не тестируем: тесты aya-backend'а нуждаются в CAP_BPF, которых на этой
// ноде у сборочного контейнера нет. Дефолтная сборка использует SimBackend.

def RUST_IMAGE = 'rust:1-bookworm'
// registry — кэш крейтов; target — под VirtioFS обязан быть томом; tools —
// под cargo-audit/cargo-deny, т.к. /usr/local/cargo/bin трогать нельзя.
def RUST_DOCKER_ARGS = '-v asmodeus-cargo-home:/usr/local/cargo/registry' +
                       ' -v asmodeus-cargo-target:/build-target' +
                       ' -v asmodeus-cargo-tools:/cargo-tools'

pipeline {
    agent none

    options {
        timestamps()
        disableConcurrentBuilds()
        buildDiscarder(logRotator(numToKeepStr: '20'))
        timeout(time: 45, unit: 'MINUTES')
    }

    environment {
        CARGO_TARGET_DIR = '/build-target'
        CARGO_TERM_COLOR = 'never'
        CARGO_INSTALL_ROOT = '/cargo-tools'
    }

    stages {
        // Первым: находка роняет билд за минуту, а не после полной сборки Rust.
        // agent any — docker CLI живёт на ноде, а не внутри rust-образа.
        stage('SAST (semgrep)') {
            agent any
            steps {
                sh '''
                    set -eu
                    # --error роняет стадию на находках ERROR, --output оставляет артефакт.
                    docker run --rm -v "$WORKSPACE":/src -w /src semgrep/semgrep:latest \
                        semgrep scan --config p/rust --config p/secrets \
                            --metrics=off --severity ERROR --error \
                            --json --output semgrep.json
                '''
            }
            post {
                always {
                    archiveArtifacts artifacts: 'semgrep.json', allowEmptyArchive: true
                }
            }
        }

        // Каждая стадия внутри — в rust-контейнере, один воркспейс на группу.
        // reuseNode true держит стадии на том же воркспейсе (JENKINS-30600).
        stage('Build') {
            agent {
                docker {
                    image RUST_IMAGE
                    args RUST_DOCKER_ARGS
                    reuseNode true
                }
            }
            stages {
                stage('Format') {
                    steps {
                        sh '''
                            set -eu
                            cargo fmt --all -- --check
                        '''
                    }
                }
                stage('Clippy') {
                    steps {
                        sh '''
                            set -eu
                            # asmodeus-proto/build.rs → tonic-build нужен protoc, которого нет
                            # в rust:1-bookworm. Ставим идемпотентно (guard на command -v),
                            # чтобы шаг был безопасен при любом переиспользовании контейнера.
                            command -v protoc >/dev/null 2>&1 || {
                                apt-get update -qq && apt-get install -y -qq protobuf-compiler
                            }
                            cargo clippy --workspace --all-targets --locked -- -D warnings
                            # feature-gated aya-backend: только компиляция, не тесты.
                            cargo clippy -p asmodeus-runner --features ebpf --all-targets --locked -- -D warnings
                        '''
                    }
                }
                stage('Test') {
                    steps {
                        sh '''
                            set -eu
                            command -v protoc >/dev/null 2>&1 || {
                                apt-get update -qq && apt-get install -y -qq protobuf-compiler
                            }
                            cargo test --workspace --locked
                        '''
                    }
                }
            }
        }

        // Supply chain последним из сборочных: cargo-audit — жёсткий гейт,
        // cargo-deny — только если в репозитории есть deny.toml (иначе нечего
        // проверять его политиками, а дефолты уронили бы билд без конфига).
        stage('Security: supply chain') {
            agent {
                docker {
                    image RUST_IMAGE
                    args RUST_DOCKER_ARGS
                    reuseNode true
                }
            }
            steps {
                sh '''
                    set -eu
                    export PATH=/cargo-tools/bin:$PATH
                    # Сборка инструментов не должна пачкать общий /build-target.
                    CARGO_TARGET_DIR=/tmp/asmodeus-tools-target
                    export CARGO_TARGET_DIR
                    command -v cargo-audit >/dev/null || cargo install --locked cargo-audit
                    if [ -f deny.toml ]; then
                        command -v cargo-deny >/dev/null || cargo install --locked cargo-deny
                    fi
                    unset CARGO_TARGET_DIR

                    if [ -f deny.toml ]; then
                        cargo deny check licenses bans sources advisories
                    else
                        echo 'deny.toml нет — cargo-deny пропущен (см. Jenkinsfile)'
                    fi
                    cargo audit --json > "$WORKSPACE/cargo-audit.json" || {
                        cat "$WORKSPACE/cargo-audit.json" >&2
                        exit 1
                    }
                '''
            }
            post {
                always {
                    archiveArtifacts artifacts: 'cargo-audit.json', allowEmptyArchive: true
                }
            }
        }
    }

    post {
        success {
            echo 'Asmodeus CI passed on Jenkins :8081'
        }
        failure {
            echo 'Asmodeus CI failed'
        }
    }
}
