<?php
/**
 * Plugin Name: Simplified User Roles
 * Plugin URI: https://github.com/KeksiLabs/simplified-user-roles
 * Description: Idea of this plugin is to reserve administrator roles only for developers and sys admins. Removes authors and contributors. Gives Editors capability to add new editors and subcsribers. Hides Administrators from editors.
 * Version: 1.0.1
 * Author: Onni Hakala
 * Author URI: https://github.com/onnimonni
 * License: MIT License
 */

namespace KeksiLabs;

use WP_User;

class Simplified_Roles {
 
  // Add our filters
  function __construct(){

    add_action( 'plugins_loaded', array(&$this, 'load_textdomain'));
    add_filter( 'views_users',    array(&$this, 'change_user_views'),10,1);
    add_action( 'init',           array(&$this, 'change_roles'));
    add_action( 'init',           array(&$this, 'allow_editor_manage_users'));
    add_action( 'pre_user_query', array(&$this, 'pre_user_query'));
    add_filter( 'editable_roles', array(&$this, 'editable_roles'));
    add_filter( 'map_meta_cap',   array(&$this, 'map_meta_cap'),10,4);

    // Remove options if deactivated
    register_deactivation_hook( __FILE__, array(&$this, 'plugin_deactivate') );
  }

  /**
   * Load plugin textdomain.
   *
   * @since 1.0.0
   */
  function load_textdomain() {
      $result = load_plugin_textdomain( 'simplified-user-roles', false, plugin_basename( dirname( __FILE__ ) ) . '/languages' ); 
  }

  /**
   * Edit different sections in the top of user listing
   * These include normally: All, Administrators, Editors, Authors, Subscribers
   *
   * @since 1.0.0
   */
  function change_user_views($views) {
    // If current user is not admin hide administrators count from authors
    if ( !current_user_can( 'manage_options' ) ) {

      // Count how many admins and remove it from total count
      $admin_count = filter_var($views['administrator'], FILTER_SANITIZE_NUMBER_INT);
      $user_count = filter_var($views['all'], FILTER_SANITIZE_NUMBER_INT);
      $all_but_admin = $user_count - $admin_count;

      // Replace the count without admins
      $views['all'] = preg_replace('/\([0-9]+\)/', '('.$all_but_admin.')', $views['all']);

      // Hide admin option
      unset($views['administrator']);
    }
    return $views;
  }

  /**
   * Remove some unneeded roles and change role names
   *
   * @since 1.0.0
   */
  function change_roles() {
      global $wp_roles;

      if ( ! isset( $wp_roles ) )
          $wp_roles = new WP_Roles();

      // Remove roles which are not used
      $wp_roles->remove_role("contributor");
      $wp_roles->remove_role("author");

      // Rename other roles for more usability
      // Change them for your language
      $wp_roles->roles['subscriber']['name'] = __('Basic User','simplified-user-roles');
      $wp_roles->role_names['subscriber'] = __('Basic User','simplified-user-roles');
      $wp_roles->roles['editor']['name'] = __('Staff','simplified-user-roles');
      $wp_roles->role_names['editor'] = __('Staff','simplified-user-roles');
      $wp_roles->roles['administrator']['name'] = __('Developer','simplified-user-roles');
      $wp_roles->role_names['administrator'] = __('Developer','simplified-user-roles');
  }

  /**
   * Give editors option to edit users
   *
   * @since 1.0.0
   */
  function allow_editor_manage_users() {
      if ( get_option( strtolower(__CLASS__).'_add_cap_editor_once' ) != 'done' ) {
       
          // let editor manage users
          $edit_editor = get_role('editor');
          $edit_editor->add_cap('edit_users');
          $edit_editor->add_cap('list_users');
          $edit_editor->add_cap('promote_users');
          $edit_editor->add_cap('create_users');
          $edit_editor->add_cap('add_users');
          $edit_editor->add_cap('delete_users');

          // Only do this once
          update_option( strtolower(__CLASS__).'_add_cap_editor_once', 'done' );
      }
  }
  /**
   * Disallow editor from choosing administrator from list of available roles
   *
   * @since 1.0.0
   */
  function editable_roles( $roles ){
    if( isset( $roles['administrator'] ) && !current_user_can('administrator') ){
      unset( $roles['administrator']);
    }
    return $roles;
  }

  /**
   * If someone is trying to edit or delete an admin and that user isn't an admin, don't allow it
   *
   * @since 1.0.0
   */
  function map_meta_cap( $caps, $cap, $user_id, $args ){
    switch( $cap ){
        case 'edit_user':
        case 'remove_user':
        case 'promote_user':
            if( isset($args[0]) && $args[0] == $user_id )
                break;
            elseif( !isset($args[0]) )
                $caps[] = 'do_not_allow';
            $other = new WP_User( absint($args[0]) );
            if( $other->has_cap( 'administrator' ) ){
                if(!current_user_can('administrator')){
                    $caps[] = 'do_not_allow';
                }
            }
            break;
        case 'delete_user':
        case 'delete_users':
            if( !isset($args[0]) )
                break;
            $other = new WP_User( absint($args[0]) );
            if( $other->has_cap( 'administrator' ) ){
                if(!current_user_can('administrator')){
                    $caps[] = 'do_not_allow';
                }
            }
            break;
        default:
            break;
    }
    return $caps;
  }

  /**
   * Hide admins from user list
   *
   * @since 1.0.0
   */
  function pre_user_query($user_search) {
    $user = wp_get_current_user();
    if (!current_user_can('manage_options')) { // Is Not Administrator - Remove Administrator
      global $wpdb;

      $user_search->query_where = 
          str_replace('WHERE 1=1', 
              "WHERE 1=1 AND {$wpdb->users}.ID IN (
                   SELECT {$wpdb->usermeta}.user_id FROM $wpdb->usermeta 
                      WHERE {$wpdb->usermeta}.meta_key = '{$wpdb->prefix}capabilities'
                      AND {$wpdb->usermeta}.meta_value NOT LIKE '%administrator%')", 
              $user_search->query_where
          );
    }
  }

  /**
   * If this plugin is deactivated return default roles back
   *
   * @since 1.0.0
   */
  function plugin_deactivate() {
    $default_roles = array(
        'administrator' => array(
            'switch_themes' => 1,
            'edit_themes' => 1,
            'activate_plugins' => 1,
            'edit_plugins' => 1,
            'edit_users' => 1,
            'edit_files' => 1,
            'manage_options' => 1,
            'moderate_comments' => 1,
            'manage_categories' => 1,
            'manage_links' => 1,
            'upload_files' => 1,
            'import' => 1,
            'unfiltered_html' => 1,
            'edit_posts' => 1,
            'edit_others_posts' => 1,
            'edit_published_posts' => 1,
            'publish_posts' => 1,
            'edit_pages' => 1,
            'read' => 1,
            'level_10' => 1,
            'level_9' => 1,
            'level_8' => 1,
            'level_7' => 1,
            'level_6' => 1,
            'level_5' => 1,
            'level_4' => 1,
            'level_3' => 1,
            'level_2' => 1,
            'level_1' => 1,
            'level_0' => 1,
            'edit_others_pages' => 1,
            'edit_published_pages' => 1,
            'publish_pages' => 1,
            'delete_pages' => 1,
            'delete_others_pages' => 1,
            'delete_published_pages' => 1,
            'delete_posts' => 1,
            'delete_others_posts' => 1,
            'delete_published_posts' => 1,
            'delete_private_posts' => 1,
            'edit_private_posts' => 1,
            'read_private_posts' => 1,
            'delete_private_pages' => 1,
            'edit_private_pages' => 1,
            'read_private_pages' => 1,
            'delete_users' => 1,
            'create_users' => 1,
            'unfiltered_upload' => 1,
            'edit_dashboard' => 1,
            'update_plugins' => 1,
            'delete_plugins' => 1,
            'install_plugins' => 1,
            'update_themes' => 1,
            'install_themes' => 1,
            'update_core' => 1,
            'list_users' => 1,
            'remove_users' => 1,
            'add_users' => 1,
            'promote_users' => 1,
            'edit_theme_options' => 1,
            'delete_themes' => 1,
            'export' => 1,
        ),
        'editor' => array(
            'moderate_comments' => 1,
            'manage_categories' => 1,
            'manage_links' => 1,
            'upload_files' => 1,
            'unfiltered_html' => 1,
            'edit_posts' => 1,
            'edit_others_posts' => 1,
            'edit_published_posts' => 1,
            'publish_posts' => 1,
            'edit_pages' => 1,
            'read' => 1,
            'level_7' => 1,
            'level_6' => 1,
            'level_5' => 1,
            'level_4' => 1,
            'level_3' => 1,
            'level_2' => 1,
            'level_1' => 1,
            'level_0' => 1,
            'edit_others_pages' => 1,
            'edit_published_pages' => 1,
            'publish_pages' => 1,
            'delete_pages' => 1,
            'delete_others_pages' => 1,
            'delete_published_pages' => 1,
            'delete_posts' => 1,
            'delete_others_posts' => 1,
            'delete_published_posts' => 1,
            'delete_private_posts' => 1,
            'edit_private_posts' => 1,
            'read_private_posts' => 1,
            'delete_private_pages' => 1,
            'edit_private_pages' => 1,
            'read_private_pages' => 1,
        ),
        'author' => array(
            'upload_files' => 1,
            'edit_posts' => 1,
            'edit_published_posts' => 1,
            'publish_posts' => 1,
            'read' => 1,
            'level_2' => 1,
            'level_1' => 1,
            'level_0' => 1,
            'delete_posts' => 1,
            'delete_published_posts' => 1,
        ),
        'contributor' => array(
            'edit_posts' => 1,
            'read' => 1,
            'level_1' => 1,
            'level_0' => 1,
            'delete_posts' => 1,
        ),
        'subscriber' => array(
            'read' => 1,
            'level_0' => 1,
        )
    );

    $display_names = array(
        'administrator' => 'Administrator',
        'editor'        => 'Editor',
        'author'        => 'Author',
        'contributor'   => 'Contributor',
        'subscriber'    => 'Subscriber'
    );

    // Return all settings to default
    foreach($default_roles as $role => $settings ) {
      remove_role( $role );
      add_role( $role, $display_names[$role], $settings );
    }

    // Remove the one time option
    delete_option( strtolower(__CLASS__).'_add_cap_editor_once' );
  }
}

new Simplified_Roles();